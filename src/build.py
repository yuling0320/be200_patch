"""Build an app-local IP Helper compatibility proxy using the existing DevEco LLVM.
Writes only in this directory. Does not deploy or execute Huawei software.
"""
from pathlib import Path
import json,subprocess,hashlib,pefile,struct
root=Path(__file__).resolve().parent
llvm=Path(r'C:\Program Files\Huawei\DevEco Studio\sdk\default\openharmony\native\llvm\bin')
system=Path(r'C:\Windows\System32\iphlpapi.dll')
pe=pefile.PE(str(system))
exports=sorted(pe.DIRECTORY_ENTRY_EXPORT.symbols,key=lambda x:x.ordinal)
assert len(exports)==313 and all(x.name for x in exports)
names=[x.name.decode('ascii') for x in exports]
index=names.index('GetAdaptersInfo')
(root/'exports.h').write_text('#define EXPORT_COUNT %d\n#define GET_ADAPTERS_INFO_INDEX %d\nstatic const char *const export_names[]={\n%s\n};\n'%(len(exports),index,',\n'.join(json.dumps(n) for n in names)))
definitions=['LIBRARY iphlpapi','EXPORTS']
stubs=['.text']
for i,e in enumerate(exports):
    name=e.name.decode('ascii')
    implementation='CompatGetAdaptersInfo' if name=='GetAdaptersInfo' else f'forward_{i}'
    definitions.append(f'  {name}={implementation} @{e.ordinal}')
    if name=='GetAdaptersInfo': continue
    # Shadow space, preserved integer/FP parameter registers, 16-byte aligned call.
    stubs.extend([f'.globl forward_{i}',f'.seh_proc forward_{i}',f'forward_{i}:',
      ' subq $168, %rsp','.seh_stackalloc 168','.seh_endprologue',' movq %rcx, 32(%rsp)',' movq %rdx, 40(%rsp)',
      ' movq %r8, 48(%rsp)',' movq %r9, 56(%rsp)',
      ' movdqu %xmm0, 64(%rsp)',' movdqu %xmm1, 80(%rsp)',
      ' movdqu %xmm2, 96(%rsp)',' movdqu %xmm3, 112(%rsp)',
      f' movl ${i}, %ecx',' callq resolve_export',
      ' movq 32(%rsp), %rcx',' movq 40(%rsp), %rdx',' movq 48(%rsp), %r8',' movq 56(%rsp), %r9',
      ' movdqu 64(%rsp), %xmm0',' movdqu 80(%rsp), %xmm1',
      ' movdqu 96(%rsp), %xmm2',' movdqu 112(%rsp), %xmm3',
      ' addq $168, %rsp',f' jmpq *real_functions+{8*i}(%rip)','.seh_endproc'])
(root/'iphlpapi.def').write_text('\n'.join(definitions)+'\n')
(root/'forwards.s').write_text('\n'.join(stubs)+'\n')
imports={
 'KERNEL32':['InitOnceExecuteOnce','LoadLibraryExW','GetProcAddress','GetSystemDirectoryW','GetModuleFileNameW','GetModuleHandleW','GetLastError','SetLastError','RaiseFailFastException','CreateFileW','ReadFile','CloseHandle','GetProcessHeap','HeapAlloc','HeapFree','GetStdHandle','WriteFile','ExitProcess','CreateThread','WaitForMultipleObjects','GetExitCodeThread'],
 'ADVAPI32':['RegGetValueA'],
 'bcrypt':['BCryptOpenAlgorithmProvider','BCryptGetProperty','BCryptCreateHash','BCryptHashData','BCryptFinishHash','BCryptDestroyHash','BCryptCloseAlgorithmProvider'],
}
def run(args):
    subprocess.run([str(a) for a in args],cwd=root,check=True)
for dll,functions in imports.items():
    definition=root/(dll+'.def')
    definition.write_text('LIBRARY '+dll+'.dll\nEXPORTS\n'+'\n'.join(functions)+'\n')
    members=[]
    for name in functions:
        data=(name+'\0'+dll+'.dll\0').encode('ascii')
        member=root/(dll+'-'+name+'.import.obj')
        member.write_bytes(struct.pack('<HHHHIIHH',0,0xffff,0,0x8664,0,len(data),0,4)+data)
        members.append(member)
    run([llvm/'llvm-lib.exe','/machine:x64','/out:'+str(root/(dll+'.lib'))]+members)
common=[llvm/'clang.exe','--target=x86_64-pc-windows-msvc','-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-Wall','-Wextra','-Werror']
run(common+['-c','proxy.c','-o','proxy.obj'])
run([llvm/'clang.exe','--target=x86_64-pc-windows-msvc','-c','forwards.s','-o','forwards.obj'])
run([llvm/'lld-link.exe','/dll','/noentry','/nodefaultlib','/machine:x64','/dynamicbase','/nxcompat','/Brepro','/def:iphlpapi.def','/out:iphlpapi.dll','proxy.obj','forwards.obj']+[dll+'.lib' for dll in imports])
out=pefile.PE(str(root/'iphlpapi.dll'))
actual={x.ordinal:x.name for x in out.DIRECTORY_ENTRY_EXPORT.symbols}
assert actual=={x.ordinal:x.name for x in exports}
manifest={
 'status':'prepared-not-deployed-unverified',
 'source_exe_sha256':'4c9501235b9ace2420976564de49c96dee2f2b0ceea4a56bdf6249957a9e03a4',
 'system_iphlpapi_sha256':hashlib.sha256(system.read_bytes()).hexdigest(),
 'candidate_sha256':hashlib.sha256((root/'iphlpapi.dll').read_bytes()).hexdigest(),
 'exports':len(actual),
 'import_dlls':[d.dll.decode() for d in out.DIRECTORY_ENTRY_IMPORT],
 'scope':'Only original HiConnectivityService.exe SHA256 and its GetAdaptersInfoExt caller; active numbered BE200 virtual adapter matching original registry IPv4; Description only.',
 'not_deployed':True,
 'preserves':'Original signed Huawei EXE and IPC Authenticode verification; real IP Helper used for all functions; no driver/registry changes.',
 'limitations':['No phone projection test yet.','App-local unsigned DLL adds code to Huawei processes; requires explicit deployment approval.','Automatic load order in the actual service not yet verified.'],
}
(root/'manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps(manifest,indent=2))

run(common+['-c','test_probe.c','-o','test_probe.obj'])
run([llvm/'lld-link.exe','/nodefaultlib','/machine:x64','/subsystem:console','/entry:mainCRTStartup','/dynamicbase','/nxcompat','/Brepro','/out:CompatProbe.exe','test_probe.obj','KERNEL32.lib','iphlpapi.lib'])

run(common+['-c','test_identity.c','-o','test_identity.obj'])
run([llvm/'lld-link.exe','/nodefaultlib','/machine:x64','/subsystem:console','/entry:mainCRTStartup','/dynamicbase','/nxcompat','/Brepro','/out:IdentityProbe.exe','test_identity.obj']+[dll+'.lib' for dll in imports])
