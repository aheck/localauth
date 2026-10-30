/*
MIT License

Copyright (c) 2026 Andreas Heck

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#pragma once
// LocalAuth: C++20, header-only local file-challenge authentication.
// No sockets. HMAC-SHA256. Platform support: Linux, macOS, Windows.
// See README.md for threat model and deployment requirements.
#include <array>
#include <tuple>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <utility>
#include <limits>
#include <system_error>
#include <cstdio>
#include <cerrno>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#endif
#elif defined(__APPLE__)
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/acl.h>
#include <membership.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>
#include <cerrno>
#endif

namespace LocalAuth {
enum class AuthError { NoError, InvalidUser, UserNotAllowed, ChallengeCreationFailed,
    PermissionDenied, ChallengeNotFound, ChallengeExpired, InvalidResponse,
    TooManyChallenges, IoError, InvalidChallenge, UnsupportedPlatform };

namespace Detail {
inline void secureErase(void* data, std::size_t size) noexcept {
#if defined(_WIN32)
    SecureZeroMemory(data, size);
#elif defined(__APPLE__)
    // memset_s requires an opt-in before any inclusion of the system string
    // header, which a header-only library cannot guarantee. Volatile stores
    // keep the erase from being optimized away.
    auto* bytes = static_cast<volatile unsigned char*>(data);
    while (size != 0) {
        *bytes++ = 0;
        --size;
    }
#else
    explicit_bzero(data, size);
#endif
}
// Scope guards also cover exceptions during allocation and container insertion.
template<class F> class ScopeExit {
    F action_;
public:
    explicit ScopeExit(F action) : action_(std::move(action)) {}
    ScopeExit(const ScopeExit&) = delete;
    ScopeExit& operator=(const ScopeExit&) = delete;
    ~ScopeExit() noexcept { action_(); }
};
template<std::size_t N> struct SecretBytes : std::array<std::uint8_t, N> {
    SecretBytes() : std::array<std::uint8_t, N>{} {}
    ~SecretBytes() { secureErase(this->data(), this->size()); }
};
using Bytes32 = SecretBytes<32>;
inline bool validUserName(const std::string& name) {
    return !name.empty() && name.size() <= 32767 && name.find('\0') == std::string::npos;
}
inline constexpr std::array<std::uint32_t,64> k = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
inline std::uint32_t rotr(std::uint32_t x, unsigned n) { return (x>>n)|(x<<(32-n)); }
class Sha256 {
    std::array<std::uint32_t,8> h_ {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::array<std::uint8_t,64> block_{};
    std::uint64_t count_ = 0;
    void compress(const std::uint8_t* p) {
        std::uint32_t w[64]{};
        ScopeExit wipe([&] { secureErase(w, sizeof(w)); });
        for (int i=0;i<16;++i) w[i]=(std::uint32_t(p[i*4])<<24)|(std::uint32_t(p[i*4+1])<<16)|(std::uint32_t(p[i*4+2])<<8)|p[i*4+3];
        for (int i=16;i<64;++i) {
            auto s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
            auto s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
            w[i]=w[i-16]+s0+w[i-7]+s1;
        }
        auto [a,b,c,d,e,f,g,h]=std::tuple{h_[0],h_[1],h_[2],h_[3],h_[4],h_[5],h_[6],h_[7]};
        for (int i=0;i<64;++i) {
            auto s1=rotr(e,6)^rotr(e,11)^rotr(e,25);
            auto t1=h+s1+((e&f)^(~e&g))+k[i]+w[i];
            auto s0=rotr(a,2)^rotr(a,13)^rotr(a,22);
            auto t2=s0+((a&b)^(a&c)^(b&c));
            h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        const std::uint32_t v[]={a,b,c,d,e,f,g,h};
        for (int i=0;i<8;++i) h_[i]+=v[i];
    }
public:
    ~Sha256() { secureErase(h_.data(), sizeof(h_)); secureErase(block_.data(), block_.size()); }
    void update(std::span<const std::uint8_t> data) {
        for (auto x:data) {
            block_[count_%64]=x;
            ++count_;
            if (count_%64==0) compress(block_.data());
        }
    }
    Bytes32 finish() {
        const auto bits=count_*8;
        std::uint8_t one=0x80, zero=0;
        update({&one,1});
        while (count_%64!=56) update({&zero,1});
        std::uint8_t len[8];
        for (int i=0;i<8;++i) len[7-i]=std::uint8_t(bits>>(i*8));
        update({len,8});
        Bytes32 out{};
        for (int i=0;i<8;++i) for (int j=0;j<4;++j) out[i*4+j]=std::uint8_t(h_[i]>>(24-j*8));
        return out;
    }
};
inline Bytes32 sha256(std::span<const std::uint8_t> input) { Sha256 s; s.update(input); return s.finish(); }
inline Bytes32 hmacSha256(const Bytes32& key, std::span<const std::uint8_t> msg) {
    SecretBytes<64> ipad{},opad{};
    for (std::size_t i=0;i<64;++i) { auto v=i<32?key[i]:0; ipad[i]=v^0x36;opad[i]=v^0x5c; }
    Sha256 inner;inner.update(ipad);inner.update(msg);auto digest=inner.finish();
    Sha256 outer;outer.update(opad);outer.update(digest);return outer.finish();
}
inline std::string hex(std::span<const std::uint8_t> bytes) {
    static constexpr char digits[]="0123456789abcdef";
    std::string out;out.reserve(bytes.size()*2);
    for (auto b:bytes) {out+=digits[b>>4];out+=digits[b&15];}return out;
}
inline bool decodeHex(std::string_view s, std::span<std::uint8_t> out) {
    if(s.size()!=out.size()*2)return false;
    auto digit=[](char c)->int {if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};
    for(std::size_t i=0;i<out.size();++i){int a=digit(s[2*i]),b=digit(s[2*i+1]);if(a<0||b<0)return false;out[i]=std::uint8_t((a<<4)|b);}return true;
}
inline bool equal(const Bytes32& a,const Bytes32& b) {unsigned d=0;for(std::size_t i=0;i<32;++i)d|=a[i]^b[i];return d==0;}
inline std::vector<std::uint8_t> message(std::string_view id,std::string_view nonce) {
    // Fixed-length ASCII hex fields make this encoding unambiguous.
    std::string s="LocalAuth/v1:";s+=id;s+=':';s+=nonce;
    return {s.begin(),s.end()};
}
inline bool randomBytes(std::span<std::uint8_t> out) {
#if defined(_WIN32)
    return BCryptGenRandom(nullptr,out.data(),static_cast<ULONG>(out.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0;
#elif defined(__APPLE__)
    arc4random_buf(out.data(),out.size());return true;
#else
    std::size_t n=0;
    while(n<out.size()) {ssize_t r=getrandom(out.data()+n,out.size()-n,0);if(r<0&&errno==EINTR)continue;if(r<=0)return false;n+=std::size_t(r);}return true;
#endif
}
inline std::filesystem::path defaultDirectory() {
#if defined(_WIN32)
    wchar_t dir[MAX_PATH+1]{};
    auto n=GetWindowsDirectoryW(dir,MAX_PATH);
    if(n==0||n>=MAX_PATH)return L"C:\\Windows\\Temp";
    return std::filesystem::path(dir)/L"Temp";
#else
    return "/tmp";
#endif
}
inline bool safeName(std::string_view name) {
    if(name.size()!=std::string_view("localauth-").size()+32+std::string_view(".challenge").size())return false;
    if(!name.starts_with("localauth-")||!name.ends_with(".challenge"))return false;
    const auto start=std::string_view("localauth-").size();
    for(auto c:name.substr(start,32))if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;
    return true;
}
inline std::optional<std::filesystem::path> checkedPath(const std::filesystem::path& directory,const std::filesystem::path& input) {
    // Compare canonical parents; reject filenames with path separators.
    auto name=input.filename().string();if(!safeName(name))return std::nullopt;
    std::error_code ec;
    auto base=std::filesystem::canonical(directory,ec);if(ec)return std::nullopt;
    auto parent=std::filesystem::canonical(input.parent_path(),ec);if(ec||parent!=base)return std::nullopt;
    return parent/input.filename();
}
#if defined(_WIN32)
inline std::optional<std::vector<std::uint8_t>> sidFor(const std::string& name) {
    if(!validUserName(name))return std::nullopt;
    int length=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name.data(),int(name.size()),nullptr,0);
    if(length<=0)return std::nullopt;
    std::wstring w(length,L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name.data(),int(name.size()),w.data(),length);
    DWORD sidSize=0,domainSize=0;SID_NAME_USE use;
    LookupAccountNameW(nullptr,w.c_str(),nullptr,&sidSize,nullptr,&domainSize,&use);
    if(!sidSize)return std::nullopt;
    std::vector<std::uint8_t> sid(sidSize);std::wstring domain(domainSize,L'\0');
    if(!LookupAccountNameW(nullptr,w.c_str(),sid.data(),&sidSize,domain.data(),&domainSize,&use))return std::nullopt;
    if(use!=SidTypeUser)return std::nullopt;
    sid.resize(sidSize);return sid;
}
using Identity = std::vector<std::uint8_t>;
inline std::optional<Identity> identityFor(const std::string& name) { return sidFor(name); }
inline std::optional<Identity> selfSid() {
    HANDLE token=nullptr;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return std::nullopt;
    ScopeExit close([&] { CloseHandle(token); });
    DWORD n=0;GetTokenInformation(token,TokenUser,nullptr,0,&n);
    if(!n)return std::nullopt;
    std::vector<std::uint8_t> buf(n);
    if(!GetTokenInformation(token,TokenUser,buf.data(),n,&n))return std::nullopt;
    auto* tu=reinterpret_cast<TOKEN_USER*>(buf.data());
    Identity sid(GetLengthSid(tu->User.Sid));
    if(!CopySid(DWORD(sid.size()),sid.data(),tu->User.Sid))return std::nullopt;
    return sid;
}
inline std::optional<Identity> selfIdentity() { return selfSid(); }
inline std::error_code nativeError() { return {int(GetLastError()),std::system_category()}; }
inline std::error_code createProtected(const std::filesystem::path& path,const Bytes32& secret,const Identity& target) {
    auto self=selfSid();if(!self)return nativeError();
    EXPLICIT_ACCESSW ea[2]{};
    ea[0].grfAccessPermissions=FILE_GENERIC_READ;ea[0].grfAccessMode=SET_ACCESS;ea[0].grfInheritance=NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm=TRUSTEE_IS_SID;ea[0].Trustee.TrusteeType=TRUSTEE_IS_USER;ea[0].Trustee.ptstrName=reinterpret_cast<LPWSTR>(const_cast<std::uint8_t*>(target.data()));
    ea[1].grfAccessPermissions=FILE_ALL_ACCESS;ea[1].grfAccessMode=SET_ACCESS;ea[1].grfInheritance=NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm=TRUSTEE_IS_SID;ea[1].Trustee.TrusteeType=TRUSTEE_IS_USER;ea[1].Trustee.ptstrName=reinterpret_cast<LPWSTR>(self->data());
    PACL acl=nullptr;
    // Avoid duplicate entries when server and client are the same account.
    const bool same=target==*self;
    DWORD status=SetEntriesInAclW(same?1:2,same?&ea[1]:ea,nullptr,&acl);
    if(status!=ERROR_SUCCESS)return {int(status),std::system_category()};
    ScopeExit freeAcl([&] { LocalFree(acl); });
    SECURITY_DESCRIPTOR sd{};
    if(!InitializeSecurityDescriptor(&sd,SECURITY_DESCRIPTOR_REVISION) ||
       !SetSecurityDescriptorOwner(&sd,self->data(),FALSE) ||
       !SetSecurityDescriptorDacl(&sd,TRUE,acl,FALSE) ||
       !SetSecurityDescriptorControl(&sd,SE_DACL_PROTECTED,SE_DACL_PROTECTED))return nativeError();
    SECURITY_ATTRIBUTES sa{sizeof(sa),&sd,FALSE};
    HANDLE h=CreateFileW(path.c_str(),GENERIC_WRITE,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(h==INVALID_HANDLE_VALUE)return nativeError();
    bool committed=false;
    ScopeExit close([&] { CloseHandle(h);if(!committed)DeleteFileW(path.c_str()); });
    DWORD n=0;
    if(!WriteFile(h,secret.data(),32,&n,nullptr))return nativeError();
    if(n!=32)return std::make_error_code(std::errc::io_error);
    if(!FlushFileBuffers(h))return nativeError();
    committed=true;return {};
}
inline bool trustedAcl(HANDLE h,const Identity& trusted,const Identity& self) {
    PSID owner=nullptr;PACL acl=nullptr;PSECURITY_DESCRIPTOR sd=nullptr;
    if(GetSecurityInfo(h,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
                       &owner,nullptr,&acl,nullptr,&sd)!=ERROR_SUCCESS)return false;
    ScopeExit freeSd([&] { LocalFree(sd); });
    if(!owner||!EqualSid(owner,const_cast<std::uint8_t*>(trusted.data()))||!acl||!IsValidAcl(acl))return false;
    SECURITY_DESCRIPTOR_CONTROL control{};DWORD revision=0;
    if(!GetSecurityDescriptorControl(sd,&control,&revision)||!(control&SE_DACL_PROTECTED))return false;
    bool ownerSeen=false,readerSeen=false;
    for(DWORD i=0;i<acl->AceCount;++i) {
        void* raw=nullptr;if(!GetAce(acl,i,&raw))return false;
        auto* ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);
        if(ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE||ace->Header.AceFlags!=0)return false;
        PSID sid=&ace->SidStart;
        if(EqualSid(sid,owner)) {
            if(ownerSeen||ace->Mask!=FILE_ALL_ACCESS)return false;
            ownerSeen=true;
        } else if(EqualSid(sid,const_cast<std::uint8_t*>(self.data()))) {
            if(readerSeen||ace->Mask!=FILE_GENERIC_READ)return false;
            readerSeen=true;
        } else return false;
    }
    return ownerSeen&&(trusted==self||readerSeen);
}
inline bool readProtected(const std::filesystem::path& path,Bytes32& out,const Identity& trusted) {
    auto self=selfIdentity();if(!self)return false;
    HANDLE h=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(h==INVALID_HANDLE_VALUE)return false;
    ScopeExit close([&] { CloseHandle(h); });
    BY_HANDLE_FILE_INFORMATION info{};LARGE_INTEGER size{};DWORD n=0;
    return GetFileType(h)==FILE_TYPE_DISK && GetFileInformationByHandle(h,&info) &&
        !(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)) && info.nNumberOfLinks==1 &&
        GetFileSizeEx(h,&size)&&size.QuadPart==32 && trustedAcl(h,trusted,*self) &&
        ReadFile(h,out.data(),32,&n,nullptr)&&n==32;
}
inline void removeFile(const std::filesystem::path& p) {DeleteFileW(p.c_str());}
#else
using Identity = uid_t;
inline std::optional<uid_t> uidFor(const std::string& name) {
    if(!validUserName(name))return std::nullopt;
    long n=sysconf(_SC_GETPW_R_SIZE_MAX);
    std::vector<char> buf(n>0&&n<1048576?std::size_t(n):16384);
    for(;;) {
        struct passwd pwd{},*result=nullptr;
        int error=getpwnam_r(name.c_str(),&pwd,buf.data(),buf.size(),&result);
        if(!error)return result?std::optional<uid_t>(pwd.pw_uid):std::nullopt;
        if(error!=ERANGE||buf.size()>=1048576)return std::nullopt;
        buf.resize(std::min(buf.size()*2,std::size_t(1048576)));
    }
}
inline std::optional<Identity> identityFor(const std::string& name) { return uidFor(name); }
inline std::optional<Identity> selfIdentity() { return geteuid(); }
inline std::error_code nativeError() { return {errno,std::generic_category()}; }
#if !defined(__APPLE__)
inline std::array<std::uint8_t,44> linuxAcl(uid_t uid) {
    std::array<std::uint8_t,44> blob{};
    auto put=[&](std::size_t offset,std::uint32_t value,unsigned bytes) {
        for(unsigned i=0;i<bytes;++i)blob[offset+i]=std::uint8_t(value>>(8*i));
    };
    put(0,2,4);
    const std::uint16_t tags[]={1,2,4,16,32},perms[]={6,4,0,4,0};
    for(unsigned i=0;i<5;++i) {
        put(4+i*8,tags[i],2);put(6+i*8,perms[i],2);
        put(8+i*8,i==1?std::uint32_t(uid):0xffffffffu,4);
    }
    return blob;
}
#endif
inline bool setUserAcl(int fd,uid_t uid) {
#if defined(__APPLE__)
    uuid_t uuid{};
    int membershipError=mbr_uid_to_uuid(uid,uuid);
    if(membershipError!=0){errno=membershipError;return false;}
    acl_t acl=acl_init(1);if(!acl)return false;
    ScopeExit freeAcl([&] { acl_free(acl); });
    acl_entry_t entry{};bool ok=acl_create_entry(&acl,&entry)==0;
    if(ok)ok=acl_set_tag_type(entry,ACL_EXTENDED_ALLOW)==0;
    if(ok)ok=acl_set_qualifier(entry,uuid)==0;
    acl_permset_t perms{};if(ok)ok=acl_get_permset(entry,&perms)==0;
    // The client needs READ_SECURITY to inspect the ACL on its open descriptor.
    if(ok)ok=acl_clear_perms(perms)==0&&acl_add_perm(perms,ACL_READ_DATA)==0&&acl_add_perm(perms,ACL_READ_SECURITY)==0;
    if(ok)ok=acl_set_permset(entry,perms)==0;
    if(ok)ok=acl_set_fd_np(fd,acl,ACL_TYPE_EXTENDED)==0;
    return ok;
#else
    auto blob=linuxAcl(uid);
    return fsetxattr(fd,"system.posix_acl_access",blob.data(),blob.size(),0)==0;
#endif
}
inline bool trustedAcl(int fd,uid_t reader) {
#if defined(__APPLE__)
    uuid_t uuid{};if(mbr_uid_to_uuid(reader,uuid)!=0)return false;
    acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);if(!acl)return false;
    ScopeExit freeAcl([&] { acl_free(acl); });
    acl_entry_t entry{};
    if(acl_get_entry(acl,ACL_FIRST_ENTRY,&entry)!=0)return false;
    acl_tag_t tag{};if(acl_get_tag_type(entry,&tag)!=0||tag!=ACL_EXTENDED_ALLOW)return false;
    void* qualifier=acl_get_qualifier(entry);if(!qualifier)return false;
    ScopeExit freeQualifier([&] { acl_free(qualifier); });
    if(std::memcmp(qualifier,uuid,sizeof(uuid))!=0)return false;
    acl_permset_mask_t mask{};
    if(acl_get_permset_mask_np(entry,&mask)!=0||mask!=(ACL_READ_DATA|ACL_READ_SECURITY))return false;
    acl_flagset_t flags{};
    if(acl_get_flagset_np(entry,&flags)!=0)return false;
    for(auto flag:{ACL_ENTRY_INHERITED,ACL_ENTRY_FILE_INHERIT,ACL_ENTRY_DIRECTORY_INHERIT,
                   ACL_ENTRY_LIMIT_INHERIT,ACL_ENTRY_ONLY_INHERIT})
        if(acl_get_flag_np(flags,flag)!=0)return false;
    // Darwin returns -1 for end of ACL (unlike Linux libacl's zero).
    errno=0;
    return acl_get_entry(acl,ACL_NEXT_ENTRY,&entry)==-1&&errno==EINVAL;
#else
    auto expected=linuxAcl(reader);std::array<std::uint8_t,44> actual{};
    return fgetxattr(fd,"system.posix_acl_access",actual.data(),actual.size())==ssize_t(actual.size())&&actual==expected;
#endif
}
inline std::error_code createProtected(const std::filesystem::path& path,const Bytes32& secret,Identity uid) {
    int fd=open(path.c_str(),O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0)return nativeError();
    bool committed=false;
    ScopeExit closeFd([&] { close(fd);if(!committed)unlink(path.c_str()); });
    if(fchmod(fd,0600)!=0)return nativeError();
    if(!setUserAcl(fd,uid))return nativeError();
    std::size_t n=0;
    while(n<32) {
        ssize_t r=write(fd,secret.data()+n,32-n);
        if(r<0&&errno==EINTR)continue;
        if(r<0)return nativeError();
        if(r==0)return std::make_error_code(std::errc::io_error);
        n+=std::size_t(r);
    }
    if(fsync(fd)!=0)return nativeError();
    committed=true;return {};
}
inline bool readProtected(const std::filesystem::path& path,Bytes32& out,Identity trusted) {
    int fd=open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0)return false;
    ScopeExit closeFd([&] { close(fd); });
    struct stat st{};
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_size!=32||st.st_nlink!=1||st.st_uid!=trusted)return false;
#if defined(__APPLE__)
    if((st.st_mode&07777)!=0600)return false;
#else
    if((st.st_mode&07777)!=0640)return false; // group bits represent the ACL mask
#endif
    if(!trustedAcl(fd,geteuid()))return false;
    std::size_t n=0;
    while(n<32) {
        ssize_t r=read(fd,out.data()+n,32-n);
        if(r<0&&errno==EINTR)continue;
        if(r<=0)return false;
        n+=std::size_t(r);
    }
    return true;
}
inline void removeFile(const std::filesystem::path& p){unlink(p.c_str());}
#endif
} // namespace Detail

class AuthChallenge {
    friend class AuthServer;
    AuthError error_=AuthError::InvalidChallenge;
    std::error_code systemError_;
    std::string id_,nonce_,userName_;
    std::filesystem::path filePath_;
public:
    explicit operator bool() const noexcept {return error_==AuthError::NoError;}
    bool isValid() const noexcept {return bool(*this);}
    AuthError error() const noexcept {return error_;}
    const std::error_code& systemError() const noexcept { return systemError_; }
    std::string errorString() const {
        if(isValid())return {};
        return systemError_?"Could not create authentication challenge: "+systemError_.message():"Could not create authentication challenge";
    }
    const std::string& id() const noexcept{return id_;}
    const std::string& nonce() const noexcept{return nonce_;}
    const std::string& userName() const noexcept{return userName_;}
    const std::filesystem::path& filePath() const noexcept{return filePath_;}
};
class AuthResponse {
    friend class AuthClient;
    AuthError error_=AuthError::InvalidChallenge;
    std::string digest_;
public:
    explicit operator bool() const noexcept{return error_==AuthError::NoError;}
    bool isValid() const noexcept{return bool(*this);}
    AuthError error() const noexcept{return error_;}
    std::string errorString() const{return isValid()?"":"Invalid or inaccessible challenge file";}
    const std::string& digest() const noexcept{return digest_;}
};
class AuthResult {
    friend class AuthServer;
    AuthError error_=AuthError::InvalidResponse;
    std::string userName_;
public:
    explicit operator bool() const noexcept{return error_==AuthError::NoError;}
    bool isAuthenticated() const noexcept{return bool(*this);}
    AuthError error() const noexcept{return error_;}
    std::string errorString() const{return isAuthenticated()?"":"Authentication failed";}
    const std::string& userName() const noexcept{return userName_;}
};
class AuthClient {
    std::filesystem::path directory_=Detail::defaultDirectory();
    std::optional<Detail::Identity> trusted_=Detail::selfIdentity();
public:
    void setChallengeDirectory(std::filesystem::path path){directory_=std::move(path);}
    const std::filesystem::path& challengeDirectory() const noexcept{return directory_;}
    // Configure from trusted application settings, never from the challenge transport.
    bool setTrustedServer(const std::string& user) {
        trusted_.reset();trusted_=Detail::identityFor(user);return trusted_.has_value();
    }
    AuthResponse createResponse(std::string_view id,const std::filesystem::path& path,std::string_view nonce) const {
        AuthResponse result;
        std::array<std::uint8_t,16> idBytes{};Detail::Bytes32 nonceBytes{};
        if(!Detail::decodeHex(id,idBytes)||!Detail::decodeHex(nonce,nonceBytes))return result;
        auto checked=Detail::checkedPath(directory_,path);if(!checked)return result;
        if(checked->filename().string()!="localauth-"+std::string(id)+".challenge")return result;
        if(!trusted_){result.error_=AuthError::PermissionDenied;return result;}
        Detail::Bytes32 secret{};
        if(!Detail::readProtected(*checked,secret,*trusted_)){result.error_=AuthError::PermissionDenied;return result;}
        auto msg=Detail::message(id,nonce);
        result.digest_=Detail::hex(Detail::hmacSha256(secret,msg));
        result.error_=AuthError::NoError;return result;
    }
};
class AuthServer {
    struct Pending {Detail::Bytes32 secret;std::string user;std::filesystem::path path;
        std::string nonce;std::chrono::steady_clock::time_point deadline;};
    mutable std::mutex mutex_;
    std::map<std::string,Pending> pending_;
    std::filesystem::path directory_=Detail::defaultDirectory();
    std::optional<std::vector<Detail::Identity>> allowed_; // nullopt = all users
    std::chrono::seconds timeout_{30};
    std::size_t maximum_=128;
    void expireLocked() {
        auto now=std::chrono::steady_clock::now();
        for(auto it=pending_.begin();it!=pending_.end();) {
            if(it->second.deadline<=now){Detail::removeFile(it->second.path);it=pending_.erase(it);}
            else ++it;
        }
    }
public:
    AuthServer()=default;
    AuthServer(const AuthServer&)=delete;
    AuthServer& operator=(const AuthServer&)=delete;
    ~AuthServer(){std::lock_guard lock(mutex_);for(auto& [id,p]:pending_)Detail::removeFile(p.path);}
    void setChallengeDirectory(std::filesystem::path p){std::lock_guard lock(mutex_);directory_=std::move(p);}
    std::filesystem::path challengeDirectory() const {std::lock_guard lock(mutex_);return directory_;}
    // Invalid configuration denies everyone, including when the return value is ignored.
    bool setAllowedUsers(const std::vector<std::string>& users) {
        std::lock_guard lock(mutex_);
        allowed_.emplace();
        std::vector<Detail::Identity> identities;
        for(const auto& user:users) {
            auto identity=Detail::identityFor(user);
            if(!identity)return false;
            identities.push_back(std::move(*identity));
        }
        allowed_=std::move(identities);return true;
    }
    void allowAllUsers(){std::lock_guard lock(mutex_);allowed_.reset();}
    void setChallengeTimeout(std::chrono::seconds t){std::lock_guard lock(mutex_);timeout_=std::max(t,std::chrono::seconds(1));}
    void setMaximumChallenges(std::size_t n){std::lock_guard lock(mutex_);maximum_=n;}
    void clearExpiredChallenges(){std::lock_guard lock(mutex_);expireLocked();}
    AuthChallenge createChallenge(const std::string& userName) {
        std::lock_guard lock(mutex_);expireLocked();AuthChallenge c;
        auto identity=Detail::identityFor(userName);
        if(!identity){c.error_=AuthError::InvalidUser;return c;}
        if(allowed_&&std::find(allowed_->begin(),allowed_->end(),*identity)==allowed_->end()) {
            c.error_=AuthError::UserNotAllowed;return c;
        }
        if(pending_.size()>=maximum_){c.error_=AuthError::TooManyChallenges;return c;}
        std::error_code ec;auto base=std::filesystem::canonical(directory_,ec);
        if(ec||!std::filesystem::is_directory(base,ec)) {
            c.error_=AuthError::IoError;c.systemError_=ec?ec:std::make_error_code(std::errc::not_a_directory);return c;
        }
        for(int attempt=0;attempt<5;++attempt){
            std::array<std::uint8_t,16> id{};Detail::Bytes32 nonce{},secret{};
            if(!Detail::randomBytes(id)||!Detail::randomBytes(nonce)||!Detail::randomBytes(secret)){
                c.error_=AuthError::IoError;return c;
            }
            c.id_=Detail::hex(id);c.nonce_=Detail::hex(nonce);
            if(pending_.contains(c.id_))continue;
            c.filePath_=base/("localauth-"+c.id_+".challenge");
            c.systemError_=Detail::createProtected(c.filePath_,secret,*identity);
            if(c.systemError_) {
                if(c.systemError_==std::errc::file_exists)continue;
                c.error_=AuthError::ChallengeCreationFailed;return c;
            }
            bool registered=false;
            Detail::ScopeExit rollback([&] { if(!registered)Detail::removeFile(c.filePath_); });
            c.userName_=userName;c.error_=AuthError::NoError;
            pending_.emplace(c.id_,Pending{secret,userName,c.filePath_,c.nonce_,std::chrono::steady_clock::now()+timeout_});
            registered=true;return c;
        }
        c.error_=AuthError::ChallengeCreationFailed;return c;
    }
    AuthResult verifyResponse(std::string_view id,std::string_view digest) {
        std::lock_guard lock(mutex_);AuthResult result;
        auto it=pending_.find(std::string(id));if(it==pending_.end()){
            result.error_=AuthError::ChallengeNotFound;return result;
        }
        // Consume before verification, including invalid responses.
        Pending p=std::move(it->second);pending_.erase(it);Detail::removeFile(p.path);
        if(std::chrono::steady_clock::now()>=p.deadline){result.error_=AuthError::ChallengeExpired;return result;}
        Detail::Bytes32 received{};
        if(!Detail::decodeHex(digest,received))return result;
        auto msg=Detail::message(id,p.nonce);
        auto expected=Detail::hmacSha256(p.secret,msg);
        bool ok=Detail::equal(expected,received);
        if(ok){result.error_=AuthError::NoError;result.userName_=std::move(p.user);}
        return result;
    }
    void cancelChallenge(std::string_view id){std::lock_guard lock(mutex_);auto it=pending_.find(std::string(id));if(it!=pending_.end()){
        Detail::removeFile(it->second.path);pending_.erase(it);
    }}
};
} // namespace LocalAuth
