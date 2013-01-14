#define _WIN32_WINNT 0x0500
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <unistd.h>
#include <winbase.h>
#include <dbghelp.h>
#include <fstream>
#include "Sugar.h"
#include "vex.h"
#include "W32Process.h"

extern "C"
int WINAPI NtQueryInformationProcess(HANDLE,DWORD,PVOID,ULONG,PULONG);

W32Process::W32Process(uint32_t _pid)
: pid(_pid)
{
	proc_h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	loadModules();
	loadThreads();
	loadLDT();
	readMappings();
}

void W32Process::readMappings(void)
{
	void*	addr;

	addr = NULL;

	/* I don't know what the user/kernel split is. fuck it */
	while ((uintptr_t)addr < 0xc0000000) {
		MEMORY_BASIC_INFORMATION	mbi, *mmap_mbi;
		SIZE_T				sz;

		sz = VirtualQueryEx(proc_h, addr, &mbi, sizeof(mbi));
		if (sz != sizeof(mbi))
			break;

		/* bump addr to next avail region */
		addr = (void*)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);

		/* ignore free regions; nothing to store */
		if (mbi.State == MEM_FREE)
			continue;

		/* found a useful region, remember it */
		mmap_mbi = new MEMORY_BASIC_INFORMATION(mbi);
		mmaps.push_back(mmap_mbi);
	}
}

void W32Process::loadModules(void)
{
	DWORD		used_bytes;
	HMODULE		hmods[1024];

	if (!EnumProcessModules(proc_h, hmods, sizeof(hmods), &used_bytes))
		return;

	for (unsigned i = 0; i < used_bytes/sizeof(HMODULE); i++) {
		TCHAR		name[MAX_PATH];
		MODULEINFO	mi;
		modinfo		modi;
		unsigned	sz = sizeof(name) / sizeof(TCHAR);

		if (!GetModuleFileNameEx(proc_h, hmods[i], name, sz))
			goto end;

		if (!GetModuleInformation(proc_h, hmods[i], &mi, sizeof(mi)))
			goto end;

		modi.mi_name = name;
		modi.mi_base = mi.lpBaseOfDll;
		modi.mi_len = mi.SizeOfImage;
		mods.push_back(modi);
end:
		CloseHandle(hmods[i]);
	}


}

W32Process::~W32Process(void)
{
	if (proc_h != NULL)
		CloseHandle(proc_h);

	foreach (it, mmaps.begin(), mmaps.end())
		delete (*it);
}

W32Process* W32Process::create(uint32_t pid)
{
	W32Process	*ret;

	ret = new W32Process(pid);
	if (ret->proc_h == NULL)
		goto fail;

	return ret;
fail:
	delete ret;
	return NULL;
}

uint64_t W32Process::getEntry(void) const
{
	return threads[0].ctx_regs.guest_EIP;
#if 0
	IMAGE_DOS_HEADER	*img_Doshdr;
	IMAGE_FILE_HEADER	*img_Filehdr;
	IMAGE_OPTIONAL_HEADER	*img_Optionalhdr;
	char			*pe;
	uint64_t		ret;
	FILE			*f;

	f = fopen(getExe().c_str(), "rb");
	if (f == NULL) {
		std::cerr << "Could not read " << getExe() << '\n';
		return 0;
	}
	
	/* XXX: fuck it */
	fread(pe, 8192, 1, f);

	img_Doshdr = (IMAGE_DOS_HEADER*)pe;
	img_Filehdr = (IMAGE_FILE_HEADER*)(pe + img_Doshdr->e_lfanew + sizeof(IMAGE_NT_SIGNATURE));
	img_Optionalhdr = (IMAGE_OPTIONAL_HEADER*)(pe + img_Doshdr->e_lfanew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER));

	ret = img_Optionalhdr->AddressOfEntryPoint;

	fclose(f);
	return ret;
#endif
}

static void ctx2vex(const CONTEXT* ctx, VexGuestX86State* vex)
{
	memset(vex, 0, sizeof(*vex));
	vex->guest_EAX = ctx->Eax;
	vex->guest_ECX = ctx->Ecx;
	vex->guest_EDX = ctx->Edx;
	vex->guest_EBX = ctx->Ebx;
	vex->guest_ESP = ctx->Esp;
	vex->guest_EBP = ctx->Ebp;
	vex->guest_ESI = ctx->Esi;
	vex->guest_EDI = ctx->Edi;
	vex->guest_DFLAG = (ctx->EFlags & (1 << 10)) ? -1 :1;
	vex->guest_IDFLAG = ctx->EFlags & (1 << 21);
	vex->guest_ACFLAG = ctx->EFlags & (1 << 18);
	vex->guest_EIP = ctx->Eip;

	/* FPU */
	for (int i = 0; i < 8; i++) {
		uint64_t v = ((uint64_t*)&(ctx->FloatSave.RegisterArea))[i];
		vex->guest_FPREG[i] = v;
	}

//	std::cerr << "[CTX2VEX] bad float control registers\n";
//	for (int i = 0; i < 8; i++)
//      UChar guest_FPTAG[8];   /* 136 */
//	vex->guest_FPROUND = ctx->;
//	vex->guest_FC3210 = ctx->;
//	vex->guest_FTOP = ctx->;

	/* SSE */
//	std::cerr << "[CTX2VEX] bad SSEROUND\n";
	// vex->guest_SSEROUND = ctx->;

//	std::cerr << "[CTX2VEX] probably wrong XMM\n";
	for (int i = 0; i < 8; i++) {
		uint64_t	v1,v2;
		v1 = ((uint64_t*)(&(ctx->ExtendedRegisters)))[2*i];
		v2 = ((uint64_t*)(&(ctx->ExtendedRegisters)))[2*i+1];
		((uint64_t*)&(vex->guest_XMM0))[2*i] = v1;
		((uint64_t*)&(vex->guest_XMM0))[2*i+1] = v2;
	}

	/* Segment registers. */
	vex->guest_CS = ctx->SegCs;
	vex->guest_DS = ctx->SegDs;
	vex->guest_ES = ctx->SegEs;
	vex->guest_FS = ctx->SegFs;
	vex->guest_GS = ctx->SegGs;
	vex->guest_SS = ctx->SegSs;
}

void W32Process::loadThreads(void)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return;

	te32.dwSize = sizeof(THREADENTRY32);
	if( !Thread32First( hThreadSnap, &te32 ) )
		goto done;

	do {
		HANDLE	th;
		CONTEXT	ctx;
		thread_ctx	tc;

		if( te32.th32OwnerProcessID != pid ) continue;

		ctx.ContextFlags = CONTEXT_FULL
			| CONTEXT_FLOATING_POINT
			| CONTEXT_EXTENDED_REGISTERS;
#ifndef __i386__
#error expected x86
#endif
		th = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
		GetThreadContext(th, &ctx);
		for (	unsigned i = 0;
			i < sizeof(tc.ctx_ldt)/sizeof(tc.ctx_ldt[0]);
			i++)
		{
			GetThreadSelectorEntry(
				th,
				i*8, /* goes by ldt offset */
				(LPLDT_ENTRY)&tc.ctx_ldt[i]);
		}
		CloseHandle(th);

		ctx2vex(&ctx, &tc.ctx_regs);
		threads.push_back(tc);
	} while(Thread32Next(hThreadSnap, &te32 ));

done:
	CloseHandle( hThreadSnap );
}


void W32Process::writeThread(
	std::ostream& os,
	std::ostream& os2,
	unsigned i) const
{
	os.write((char*)&threads[i].ctx_regs, sizeof(VexGuestX86State));
	os2.write((char*)&threads[i].ctx_ldt, sizeof(threads[i].ctx_ldt));
}

void W32Process::writeThreads(const char* path) const
{
	char	f_path[512];

	sprintf(f_path, "%s/threads", path);
	mkdir(f_path);
	for (unsigned i = 0; i < getNumThreads(); i++) {
		sprintf(f_path, "%s/threads/%d", path, i);
		std::ofstream	of(f_path, std::ios::binary);
		sprintf(f_path, "%s/threads/%d.gdt", path, i);
		std::ofstream	of2(f_path, std::ios::binary);
		writeThread(of, of2, i);
	}

	sprintf(f_path, "%s/regs", path);
	std::ofstream	of(f_path, std::ios::binary);
	sprintf(f_path, "%s/regs.gdt", path);
	std::ofstream	of2(f_path, std::ios::binary);
	writeThread(of, of2,  0);

	sprintf(f_path, "%s/regs.ldt", path);
	std::ofstream	of3(f_path, std::ios::binary);
	of3.write((char*)&ctx_gdt, sizeof(ctx_gdt));
}

void W32Process::loadLDT(void)
{
	memset(ctx_gdt, 0, sizeof(ctx_gdt));
	for (unsigned i = 0; i < VEX_GUEST_X86_GDT_NENT; i++) {
		DWORD buf[4], len;
		buf[0] = i*8 & 0xFFFFFFF8;  // selector --> offset
		buf[1] = 8; // size (multiple selectors may be added)
		// google uses -1, I guess that means for self handle?
		int res = NtQueryInformationProcess(proc_h,10,buf,16,&len);
		memcpy(&ctx_gdt[i], &buf[2], 8);
	}
}

void W32Process::writeMapInfo(const char* path) const
{
	char	s[512];
	FILE	*f;

	/* mapinfo */
	/* EX: 0x7f63cc677000-0x7f63cc678000 1 0 /lib64/libm-2.16.so */
	sprintf(s, "%s/mapinfo", path);
	f = fopen(s, "wb");
	
	for (unsigned i = 0; i < mmaps.size(); i++) {
		int		flags = 0;

		if (mmaps[i]->Protect & PAGE_NOACCESS) continue;
		if (mmaps[i]->Protect & PAGE_GUARD) continue;

		if (mmaps[i]->Protect & PAGE_READONLY) flags |= 1;//PROT_READ;
		if (mmaps[i]->Protect & PAGE_WRITECOPY) flags |= 2;//PROT_WRITE;
		if (mmaps[i]->Protect & PAGE_READWRITE) flags |= 3;//PROT_READ;
		if (mmaps[i]->Protect & PAGE_EXECUTE_READ)
			flags |= 5;//PROT_READ | PROT_EXEC;
		if (mmaps[i]->Protect & PAGE_EXECUTE_WRITECOPY)
			flags |= 6;//PROT_WRITE | PROT_EXEC;

		std::string	s = findModName(mmaps[i]->BaseAddress);

		fprintf(f, "%p-%p %d 0 %s\n",
			mmaps[i]->BaseAddress,
			(uint8_t*)(mmaps[i]->BaseAddress)+mmaps[i]->RegionSize,
			flags,
			s.c_str());
	}
	fclose(f);

}

void W32Process::writeMaps(const char* path) const
{
	char	s[512];
	FILE	*f;

	sprintf(s, "%s/maps", path);
	mkdir(s);

	for (unsigned i = 0; i < mmaps.size(); i++) {
		bool ok;
		if (mmaps[i]->Protect & PAGE_NOACCESS) continue;
		if (mmaps[i]->Protect & PAGE_GUARD) continue;

		if (mmaps[i]->Protect == 0) {
			std::cerr << "NO ACCESS TO "
				<< mmaps[i]->BaseAddress << "--"
				<< (void*)((char*)mmaps[i]->BaseAddress +
					mmaps[i]->RegionSize)
				<< '\n';
			continue;
		}

		sprintf(s, "%s/maps/0x%x", path, (unsigned int)mmaps[i]->BaseAddress);
		std::ofstream	of(s, std::ios::binary);

		ok = writeMemoryRegion(mmaps[i], of);

		if (!ok) std::cerr << GetLastError() << "-- OOPS!\n";
		assert (ok && "BAD MEMORY WRITE?");
	}

}

void W32Process::writeMemory(const char* path) const
{
	writeMapInfo(path);
	writeMaps(path);
}

std::string W32Process::findModName(void* base) const
{
	for (unsigned i = 0; i < mods.size(); i++) {
		if (base == mods[i].mi_base)
			return mods[i].mi_name;
	}

	return "??MODULE??";
}

bool W32Process::writeMemoryRegion(
	const MEMORY_BASIC_INFORMATION* mi, std::ostream& os) const
{
	for (unsigned i = 0; i < mi->RegionSize / 4096; i++) {
		BOOL	ok;
		SIZE_T	br;
		char	page[4096];

		ok = ReadProcessMemory(
			proc_h,
			((char*)mi->BaseAddress) + 4096*i,
			&page, 4096, &br);

		if (!ok || br != 4096) {
			std::cerr << "OOPS: br=" << br << ". ADDR=" <<
				(void*)(((char*)mi->BaseAddress) + 4096*i) << '\n';
			return false;
		}

		os.write(page, 4096);
	}

	return true;
}

static BOOL enum_cb(LPSTR s, ULONG x, ULONG y, std::ostream* osp)
{
	std::ostream& os(*osp);
	os << s << ' ' << (void*)x << "-" << (void*)(x + y) << '\n';
	return TRUE;
}

void W32Process::writeSymbols(std::ostream& os) const
{
	BOOL			ok;
	char			buf[1024];
	PIMAGEHLP_SYMBOL	sym = (PIMAGEHLP_SYMBOL)&buf;


	ok = SymInitialize(proc_h, NULL, TRUE);
	assert(ok);

	#if 0
	for (unsigned i = 0; i < mods.size(); i++) {
		std::cerr << "KEEP GOING!! " << mods[i].mi_name << "\n";
		SymEnumerateSymbols(
			proc_h,
			(DWORD)mods[i].mi_base,
			(PSYM_ENUMSYMBOLS_CALLBACK)enum_cb,
			(void*)&os);
	}
#endif
#if 1
	memset(sym, 0, 1024);
	sym->SizeOfStruct = 1024;
	sym->MaxNameLength = 512;

	for (unsigned j = 0; j < mods.size(); j++) {
	for (unsigned i = 0; i < mods[j].mi_len; i++) {
		DWORD	disp;
		ok = SymGetSymFromAddr(
			proc_h,
			((DWORD)mods[j].mi_base)+i,
			&disp,
			sym);
		if (ok) { break; }
	}

	while (SymGetSymNext(proc_h, sym)) {
		os	<< (char*)&sym->Name << ' '
			<< (void*)sym->Address << "-"
			<< (void*)(sym->Address + sym->Size)
			<< '\n';
	}
	}
	#endif

	SymCleanup(proc_h);
}
