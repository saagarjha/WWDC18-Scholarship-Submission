//: # Inside Playgrounds
//: #### A semi-deep dive into how Swift Playgrounds works
// We'll need these for later.
import MachO
import MessageUI
import PlaygroundSupport
import UIKit
//: - Callout(Why this topic, instead of a standard playground?):
//: It's kind of a long story; essentially, my original project idea ended up pushing the limits of what Playgrounds could do, which led me to take the Playgrounds app apart to see what exactly it allowed me to do. Unfortunately, a combination of factors (missing entitlements, changes in iOS 11) ended up coming together to make it impossible for my project to work in Swift Playgrounds. Thus, I was left with nothing to show for my time other than a general understanding of how Playgrounds worked. Since I didn't have time to come up with another project idea, I decided to do this instead.

//: - Note: This information was gleaned through reverse engineering; as such, there may be parts that are inaccurate or wholly incorrect.

//: Ok, that's enough backstory; let's dive right in.
//: ### App architecture
//: A quick peek inside Playground's IPA file will show that it's built in a modular fashion: while there's the main binary, which handles the majority of the user interface, it also has no fewer than five plugins. Swift Playgrounds needs to compile and execute the code that it's given, so it's no surprise that these handle the auxiliary tasks of providing code completion, validating entered code, compiling, linking, and finally executing playgrounds. We'll be focusing on the execution portion, since this is the only portion that we can actually easily reverse engineer, for reasons we'll see shortly.
//: ### Execution of playgrounds
//: Swift Playgrounds are distributed as source files, which are then compiled into a shared library and dynamically loaded and run. Obviously, this poses a security issue, since we're essentially allowing for the execution of arbitrary code. Clearly, this is not something we'd like to be doing in the main process, since that would give the playground control over the whole app. Thus, playgrounds are actually executed out-of-process in a one of the plugins we mentioned earlier, and app extension named ExecutionExtension. Its sole purpose is to run this code, display a live view if necessary, and report progress back to the host app. This isn't clear at a first glance, though; if you were to download the Swift Playgrounds IPA and tried disassembling the ExecutionExtension binary, you'd be stymied by FairPlay. However, there's a loophole here: since ExecutionExtension runs our code, we're in the same process as it is. This allows us to read it directly out of memory, post-decryption. Let's see if we can find it:

var info = task_dyld_info(all_image_info_addr: 0, all_image_info_size: 0, all_image_info_format: 0)
var imageCount = mach_msg_type_number_t(MemoryLayout<task_dyld_info_data_t>.size / MemoryLayout<natural_t>.size)
withUnsafePointer(to: &info) {
	task_info(mach_task_self_, task_flavor_t(TASK_DYLD_INFO), unsafeBitCast($0, to: task_info_t.self), &imageCount)
}
let allImageInfos = UnsafePointer<dyld_all_image_infos>(bitPattern: UInt(info.all_image_info_addr))!.pointee
//: Ok, that should get us all the images in this process. Is ExecutionExtension there? It should the be first thing in the list, since it's loaded first.
let path = String(cString: allImageInfos.infoArray.pointee.imageFilePath)
//: Yes, it looks like that's it! Let's try dumping it.
let size = try FileManager.default.attributesOfItem(atPath: path)[.size] as! Int
let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
defer {
	buffer.deallocate(capacity: size)
}
var count: vm_size_t = 0
vm_read_overwrite(mach_task_self_, unsafeBitCast(allImageInfos.infoArray.pointee.imageLoadAddress, to: vm_address_t.self), vm_size_t(size), unsafeBitCast(buffer, to: vm_address_t.self), &count)
//: Yep, that looks like a valid (64-bit) Mach-O header to me!
String(format: "%2x", buffer[0])
String(format: "%2x", buffer[1])
String(format: "%2x", buffer[2])
String(format: "%2x", buffer[3])
//: Ok, let's get this off the device
let mailComposeController = MFMailComposeViewController()
mailComposeController.addAttachmentData(Data(bytes: Array(UnsafeBufferPointer(start: buffer, count: size))), mimeType: "applicaton/octet-stream", fileName: (path as NSString).lastPathComponent)
let window = UIWindow()
let viewController = UIViewController()
window.rootViewController = viewController
window.makeKeyAndVisible()
PlaygroundPage.current.liveView = window
viewController.present(mailComposeController, animated: true, completion: nil)
//: All done. Ready to load into a disassembler at your leisure!
//: ### Execution
//: So after all this, how does ExecutionExtension actually *execute* our code? A quick look at the disassembly will show that it calls `dlopen`, then `dlsym`s for "main", which it then executes in some way. Can we see this in a backtrace?
Thread.callStackSymbols
//: There's only one frame from ExecutionExtension here and a bunch from CoreFoundation. What's going on? It turns out that's just CFRunLoop stuff; the code that actually calls does the `dlsym` is gone because it was on a previous run loop iteration. So we have multiple methods here in the ExecutionExtension binary. What even are they? The symbols are stripped, so we're not going to get them statically. Luckily the Objective-C runtime can help us here.
var numberOfThings: UInt32 = 0
let classes = objc_copyClassNamesForImage(path, &numberOfThings)!
var classNames = [String]()
for i in 0..<numberOfThings {
	classNames.append(String(cString: classes[Int(i)]))
}
classNames
//: Interesting. We've got some sort of view controller and line classes. Let's check out the view controller; it's probably what manages execution and contains the live view as well.
let cls: AnyClass? = NSClassFromString("PGEExecutionExtensionViewController")
let methods = class_copyMethodList(cls, &numberOfThings)!
var methodNames = [String]()
for i in 0..<numberOfThings {
	methodNames.append(method_getName(methods[Int(i)]).description)
}
methodNames
//: `executeMachOBundle:usingSandboxExtension:` looks interesting. Let's dig in more.
let method = UnsafeRawPointer(class_getMethodImplementation(cls, Selector("executeMachOBundle:usingSandboxExtension")))!
var dlinfo = dl_info(dli_fname: "", dli_fbase: nil, dli_sname: "", dli_saddr: nil)
dladdr(method, &dlinfo)
method - UnsafeRawPointer(dlinfo.dli_fbase)
//: Now we can cross reference our binary we dumped earlier; we have an offset into it. Yep, it's the function with `dlopen` we found earlier.
//: ### Other functionality
//: It's worth taking a quick look at the other functionality that is necessary for execution to work correctly. `PGEExecutionExtensionViewController` seems to be the main point of contact with the rest of the app, since it implemenents `NSXPCListener`. It also handles the reporting of execution progress, as well as managing the live view. Line-by-line step through is done in an interesting way: it's a combined effort by both the compiler and the execution extensions. When compiling, calls to _pgr_before_pc and _pgr_after_pc get automatically inserted between each statement, and these functions (which are defined in the _PlaygroundRuntime framework) are then set to whatever they need to be. They're available for use directly, as `@convention(c) (Int, Int, Int, Int) -> ()` functions, but I haven't been able to get them to do anything useful yet.
_pgr_before_pc
_pgr_after_pc
//: Assigning to them causes execution to be interrupted, possibly because of infinite recursion. Similarly, the previews that appear in the sidebar come from "logging" code that's sprinkled throughout the compiled binary.
//: ### Sandboxing
//: Obviously, it would be bad if anyone could load arbitrary code, which is why code generally needs to be code signed before `dlopen` will accept it. This isn't possible with Swift Playgrounds, so it gets a special exception: it has the "com.apple.private.amfi.can-execute-cdhash" entitlement. I'm guessing here, but what I think happens is that the main binary gets an exception from amfid and passes it to ExecutionExtension, which consumes it. Anyways, that's how far I got, I hope you enjoyed it!
