//! Give Windows the icon sizes it actually asks for.
//!
//! The taskbar does not read the executable's icon resource for a running
//! window: it asks the window itself, with `WM_GETICON`. Tauri sets a single
//! bitmap, from which Windows derives a 16x16 small icon and then stretches it
//! to whatever the display scaling wants — at 125% the taskbar draws 30x30, so
//! a 16x16 source is blown up nearly twice its size. That is the blur, and no
//! amount of care in the artwork fixes it.
//!
//! The icon file is compiled in and the right frame is picked out of it for
//! each slot, so both are downscales rather than upscales, and there is no file
//! to find at runtime. None of this is required for the program to work, so
//! every failure here is silent.

#![cfg(windows)]

use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateIconFromResourceEx, LookupIconIdFromDirectoryEx, SendMessageW, ICON_BIG, ICON_SMALL,
    LR_DEFAULTCOLOR, WM_SETICON,
};

/// The same multi-frame icon the executable ships, carried in the binary.
const ICO: &[u8] = include_bytes!("../icons/icon.ico");

/// Version stamp `CreateIconFromResourceEx` expects for icon resources.
const ICON_RESOURCE_VERSION: u32 = 0x0003_0000;

/// Pull one frame out of the icon directory and turn it into an `HICON`.
///
/// `LookupIconIdFromDirectoryEx` chooses the best-matching frame for the
/// requested size, which is the whole reason for shipping several.
fn frame(size: i32) -> isize {
    unsafe {
        let offset = LookupIconIdFromDirectoryEx(ICO.as_ptr(), 1, size, size, LR_DEFAULTCOLOR);
        if offset <= 0 || offset as usize >= ICO.len() {
            return 0;
        }
        let image = &ICO[offset as usize..];
        CreateIconFromResourceEx(
            image.as_ptr(),
            image.len() as u32,
            1,
            ICON_RESOURCE_VERSION,
            size,
            size,
            LR_DEFAULTCOLOR,
        ) as isize
    }
}

/// Point a window's small and large icons at frames that fit.
///
/// The small icon is what the taskbar and title bar draw, the large one what
/// Alt+Tab uses. Both are deliberately over-sized rather than under: Windows
/// scales whatever it is handed, and shrinking a frame looks fine where
/// stretching one does not.
pub fn apply(hwnd: isize) {
    if hwnd == 0 {
        return;
    }
    // 32 covers the taskbar and title bar without stretching. For the large
    // icon, ask for the sizes Alt+Tab actually uses and take the first that
    // loads: a 256px request returns nothing here, so reaching for the biggest
    // frame available would leave the window with no large icon at all.
    let small = frame(32);
    let big = [48, 64, 128, 96, 32]
        .into_iter()
        .map(frame)
        .find(|h| *h != 0)
        .unwrap_or(0);
    unsafe {
        let hwnd = hwnd as HWND;
        if small != 0 {
            SendMessageW(hwnd, WM_SETICON, ICON_SMALL as WPARAM, small as LPARAM);
        }
        if big != 0 {
            SendMessageW(hwnd, WM_SETICON, ICON_BIG as WPARAM, big as LPARAM);
        }
    }
}
