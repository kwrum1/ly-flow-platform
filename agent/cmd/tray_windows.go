//go:build windows

package main

import (
	"runtime"
	"syscall"
	"unsafe"
)

const (
	lyTrayCallbackMessage = 0x0400 + 1
	lyNIFMessage          = 0x00000001
	lyNIFIcon             = 0x00000002
	lyNIFTip              = 0x00000004
	lyWMDestroy           = 0x0002
	lyIDIApplication      = 32512
)

type lyPoint struct {
	X int32
	Y int32
}

type lyMsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      lyPoint
}

type lyWndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type lyNotifyIconData struct {
	Size             uint32
	Wnd              uintptr
	ID               uint32
	Flags            uint32
	CallbackMessage  uint32
	Icon             uintptr
	Tip              [128]uint16
	State            uint32
	StateMask        uint32
	Info             [256]uint16
	TimeoutOrVersion uint32
	InfoTitle        [64]uint16
	InfoFlags        uint32
	GuidItem         [16]byte
	BalloonIcon      uintptr
}

var (
	lyUser32                = syscall.NewLazyDLL("user32.dll")
	lyShell32               = syscall.NewLazyDLL("shell32.dll")
	lyProcRegisterClassEx   = lyUser32.NewProc("RegisterClassExW")
	lyProcCreateWindowEx    = lyUser32.NewProc("CreateWindowExW")
	lyProcDefWindowProc     = lyUser32.NewProc("DefWindowProcW")
	lyProcGetMessage        = lyUser32.NewProc("GetMessageW")
	lyProcTranslateMessage  = lyUser32.NewProc("TranslateMessage")
	lyProcDispatchMessage   = lyUser32.NewProc("DispatchMessageW")
	lyProcLoadIcon          = lyUser32.NewProc("LoadIconW")
	lyProcShellNotifyIcon   = lyShell32.NewProc("Shell_NotifyIconW")
	lyTrayWindowClass       = syscall.StringToUTF16Ptr("LyFlowAgentTrayWindow")
	lyTrayWindowTitle       = syscall.StringToUTF16Ptr("LyFlow Agent")
	lyTrayWindowProcPointer = syscall.NewCallback(lyTrayWindowProc)
)

func startPlatformUI() {
	go runWindowsTrayIcon()
}

func runWindowsTrayIcon() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	icon, _, _ := lyProcLoadIcon.Call(0, uintptr(lyIDIApplication))
	wc := lyWndClassEx{
		Size:      uint32(unsafe.Sizeof(lyWndClassEx{})),
		WndProc:   lyTrayWindowProcPointer,
		Instance:  0,
		ClassName: lyTrayWindowClass,
		Icon:      icon,
		IconSm:    icon,
	}
	lyProcRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))
	hwnd, _, _ := lyProcCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(lyTrayWindowClass)),
		uintptr(unsafe.Pointer(lyTrayWindowTitle)),
		0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	)
	if hwnd == 0 {
		return
	}

	data := lyNotifyIconData{
		Size:            uint32(unsafe.Sizeof(lyNotifyIconData{})),
		Wnd:             hwnd,
		ID:              1,
		Flags:           lyNIFMessage | lyNIFIcon | lyNIFTip,
		CallbackMessage: lyTrayCallbackMessage,
		Icon:            icon,
	}
	copy(data.Tip[:], syscall.StringToUTF16("流影 Agent 正在运行"))
	lyProcShellNotifyIcon.Call(0x00000000, uintptr(unsafe.Pointer(&data)))
	defer lyProcShellNotifyIcon.Call(0x00000002, uintptr(unsafe.Pointer(&data)))

	var msg lyMsg
	for {
		ret, _, _ := lyProcGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			return
		}
		lyProcTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		lyProcDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func lyTrayWindowProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	if msg == lyWMDestroy {
		return 0
	}
	ret, _, _ := lyProcDefWindowProc.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}
