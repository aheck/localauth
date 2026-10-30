#include "LocalAuth.h"
#include <iostream>
#include <stdexcept>
#include <atomic>
#include <thread>
#if !defined(_WIN32)
#include <grp.h>
#include <sys/wait.h>
#endif

namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::string currentUser() {
#if defined(_WIN32)
    auto sid = LocalAuth::Detail::selfSid();
    check(bool(sid), "Cannot obtain process SID");
    DWORD nameSize = 0, domainSize = 0;
    SID_NAME_USE use{};
    LookupAccountSidW(nullptr, sid->data(), nullptr, &nameSize, nullptr, &domainSize, &use);
    std::wstring name(nameSize, L'\0'), domain(domainSize, L'\0');
    check(LookupAccountSidW(nullptr, sid->data(), name.data(), &nameSize,
                           domain.data(), &domainSize, &use) != 0, "Cannot resolve process SID");
    name.resize(nameSize);
    domain.resize(domainSize);
    auto qualified = domain.empty() ? name : domain + L"\\" + name;
    int n = WideCharToMultiByte(CP_UTF8, 0, qualified.data(), int(qualified.size()),
                                nullptr, 0, nullptr, nullptr);
    check(n > 0, "Cannot encode account name");
    std::string result(n, '\0');
    check(WideCharToMultiByte(CP_UTF8, 0, qualified.data(), int(qualified.size()),
                             result.data(), n, nullptr, nullptr) == n, "Cannot encode account name");
    return result;
#else
    auto* pw = getpwuid(getuid());
    check(pw != nullptr, "Cannot resolve current UID");
    return pw->pw_name;
#endif
}

struct TemporaryDirectory {
    std::filesystem::path path;
    explicit TemporaryDirectory(const std::filesystem::path& base=std::filesystem::temp_directory_path()) {
        LocalAuth::Detail::Bytes32 random{};
        check(LocalAuth::Detail::randomBytes(random), "Random generator failed");
        path = base / ("localauth-test-" + LocalAuth::Detail::hex(random));
        check(std::filesystem::create_directory(path), "Cannot create test directory");
    }
    ~TemporaryDirectory() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

void cryptoTests() {
    using namespace LocalAuth;
    {
        std::array<unsigned char, 34> bytes;
        bytes.fill(0xa5);
        Detail::secureErase(bytes.data() + 1, 32);
        check(bytes.front() == 0xa5 && bytes.back() == 0xa5,
              "Secure erase wrote outside the requested range");
        check(std::all_of(bytes.begin() + 1, bytes.end() - 1,
                          [](unsigned char byte) { return byte == 0; }),
              "Secure erase did not clear the requested range");
        Detail::secureErase(bytes.data(), 0);
        check(bytes.front() == 0xa5, "Zero-length secure erase changed data");
    }
    {
        const std::string input(55, 'a');
        check(Detail::hex(Detail::sha256({reinterpret_cast<const std::uint8_t*>(input.data()), input.size()})) ==
              "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318", "SHA-256 boundary vector failed");
    }
    {
        const std::string input(56, 'a');
        check(Detail::hex(Detail::sha256({reinterpret_cast<const std::uint8_t*>(input.data()), input.size()})) ==
              "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a", "SHA-256 boundary vector failed");
    }
    {
        const std::string input(63, 'a');
        check(Detail::hex(Detail::sha256({reinterpret_cast<const std::uint8_t*>(input.data()), input.size()})) ==
              "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34", "SHA-256 boundary vector failed");
    }
    {
        const std::string input(64, 'a');
        check(Detail::hex(Detail::sha256({reinterpret_cast<const std::uint8_t*>(input.data()), input.size()})) ==
              "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb", "SHA-256 boundary vector failed");
    }
    {
        const std::string input(65, 'a');
        check(Detail::hex(Detail::sha256({reinterpret_cast<const std::uint8_t*>(input.data()), input.size()})) ==
              "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0", "SHA-256 boundary vector failed");
    }
    {
        const std::string input(128, 'a');
        check(Detail::hex(Detail::sha256({reinterpret_cast<const std::uint8_t*>(input.data()), input.size()})) ==
              "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e", "SHA-256 boundary vector failed");
    }

    check(Detail::hex(Detail::sha256({})) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 empty vector failed");
    // RFC 4231 case 2: zero-padding Jefe to 32 bytes preserves its HMAC key.
    Detail::Bytes32 key{};
    std::memcpy(key.data(), "Jefe", 4);
    const std::string msg = "what do ya want for nothing?";
    auto mac = Detail::hmacSha256(key, {reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()});
    check(Detail::hex(mac) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "HMAC-SHA256 vector failed");
    for(unsigned i=0;i<32;++i)key[i]=static_cast<std::uint8_t>(i);
    const std::string longMessage(128,'a');
    check(Detail::hex(Detail::hmacSha256(key,{reinterpret_cast<const std::uint8_t*>(longMessage.data()),longMessage.size()})) ==
          "acf2569f575039b8cbb14fa3039a4c58926d8cbc6453cdffef8a7bcd86d1173e", "Multi-block HMAC vector failed");

}

void hardeningTests() {
    using namespace LocalAuth;
    TemporaryDirectory directory;
    const auto user=currentUser();
    AuthServer server;AuthClient client;
    server.setChallengeDirectory(directory.path);client.setChallengeDirectory(directory.path);
    auto challenge=server.createChallenge(user);
    check(bool(challenge), "Hardening fixture creation failed");
    auto respond=[&] { return client.createResponse(challenge.id(),challenge.filePath(),challenge.nonce()); };
    check(bool(respond()), "Valid ACL rejected");
    check(!client.setTrustedServer(user+std::string("\0invalid",8)), "NUL trusted account accepted");
    check(!respond(), "Invalid trusted account did not fail closed");
    check(client.setTrustedServer(user), "Trusted account rejected");
    check(!server.setAllowedUsers({user,user+std::string("\0invalid",8)}), "NUL allowlist entry accepted");
    check(server.createChallenge(user).error()==AuthError::UserNotAllowed, "Invalid allowlist did not fail closed");
    check(server.createChallenge(user+std::string("\0invalid",8)).error()==AuthError::InvalidUser, "NUL account accepted");
    server.allowAllUsers();
#if defined(_WIN32)
    auto alias=user;
    for(char& c:alias) {
        if(c>='a'&&c<='z')c=char(c-'a'+'A');
        else if(c>='A'&&c<='Z')c=char(c-'A'+'a');
    }
    check(server.setAllowedUsers({alias}), "Cannot resolve Windows account alias");
    auto aliasChallenge=server.createChallenge(user);
    check(bool(aliasChallenge), "Allowlist did not match canonical SID");
    server.cancelChallenge(aliasChallenge.id());
#else
    check(client.setTrustedServer("nobody"), "Cannot resolve alternate owner");
    check(!respond(), "Wrong trusted owner accepted");
    check(client.setTrustedServer(user), "Cannot restore trusted owner");
#endif
    check(!client.createResponse(std::string(32,'f'),challenge.filePath(),challenge.nonce()), "Mismatched filename accepted");
    check(!client.createResponse(challenge.id(),challenge.filePath(),"bad nonce"), "Malformed nonce accepted");
    TemporaryDirectory other;
    client.setChallengeDirectory(other.path);
    check(!respond(), "File outside configured directory accepted");
    client.setChallengeDirectory(directory.path);

    // Creation collisions must preserve the existing file and be distinguishable.
    Detail::Bytes32 secret{};
    auto identity=Detail::identityFor(user);
    check(bool(identity), "Cannot resolve test identity");
    auto collision=Detail::createProtected(challenge.filePath(),secret,*identity);
    check(collision==std::errc::file_exists, "Creation collision not reported");
    check(bool(respond()), "Collision damaged existing challenge");

    auto link=directory.path/"extra-link";
    std::filesystem::create_hard_link(challenge.filePath(),link);
    check(!respond(), "Hard-linked challenge accepted");
    std::filesystem::remove(link);
    for(auto length:{0,31,33}) {
        std::filesystem::resize_file(challenge.filePath(),length);
        check(!respond(), "Malformed file length accepted");
    }
    std::filesystem::resize_file(challenge.filePath(),32);
#if defined(_WIN32)
    std::array<std::uint8_t,SECURITY_MAX_SID_SIZE> everyone{};
    DWORD sidSize=DWORD(everyone.size());
    check(CreateWellKnownSid(WinWorldSid,nullptr,everyone.data(),&sidSize)!=0, "Cannot create Everyone SID");
    EXPLICIT_ACCESSW entry{};
    entry.grfAccessPermissions=FILE_ALL_ACCESS;entry.grfAccessMode=SET_ACCESS;
    entry.Trustee.TrusteeForm=TRUSTEE_IS_SID;
    entry.Trustee.ptstrName=reinterpret_cast<LPWSTR>(everyone.data());
    PACL broadAcl=nullptr;
    check(SetEntriesInAclW(1,&entry,nullptr,&broadAcl)==ERROR_SUCCESS, "Cannot create broad DACL");
    Detail::ScopeExit freeAcl([&] { LocalFree(broadAcl); });
    check(SetNamedSecurityInfoW(const_cast<wchar_t*>(challenge.filePath().c_str()),SE_FILE_OBJECT,
          DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,broadAcl,nullptr)==ERROR_SUCCESS,
          "Cannot set broad DACL");
    check(!respond(), "Everyone DACL accepted");
    // A NULL DACL grants everyone access and must be rejected.
    check(SetNamedSecurityInfoW(const_cast<wchar_t*>(challenge.filePath().c_str()),SE_FILE_OBJECT,
          DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,nullptr,nullptr)==ERROR_SUCCESS,
          "Cannot mutate test DACL");
    check(!respond(), "NULL DACL accepted");
#else
#if defined(__APPLE__)
    acl_t acl=acl_get_file(challenge.filePath().c_str(),ACL_TYPE_EXTENDED);
    check(acl!=nullptr, "Cannot read test ACL");
    Detail::ScopeExit freeAcl([&] { acl_free(acl); });
    acl_entry_t entry{};acl_permset_t perms{};
    check(acl_get_entry(acl,ACL_FIRST_ENTRY,&entry)==0&&acl_get_permset(entry,&perms)==0&&
          acl_add_perm(perms,ACL_WRITE_DATA)==0&&acl_set_permset(entry,perms)==0&&
          acl_set_file(challenge.filePath().c_str(),ACL_TYPE_EXTENDED,acl)==0, "Cannot broaden test ACL");
#else
    auto broadAcl=Detail::linuxAcl(*identity);
    broadAcl[22]=4; // grant owning group read access without changing the ACL mask/mode
    check(setxattr(challenge.filePath().c_str(),"system.posix_acl_access",broadAcl.data(),broadAcl.size(),0)==0,
          "Cannot broaden test ACL");
#endif
    check(!respond(), "Broader ACL with unchanged mode accepted");
    check(chmod(challenge.filePath().c_str(),0644)==0, "Cannot mutate test mode");
    check(!respond(), "World-readable challenge accepted");
    std::filesystem::remove(challenge.filePath());
    auto target=other.path/"target";
    check(!Detail::createProtected(target,secret,*identity), "Cannot create symlink target");
    std::filesystem::create_symlink(target,challenge.filePath());
    check(!respond(), "Symlink challenge accepted");
    std::filesystem::remove(challenge.filePath());
    check(mkfifo(challenge.filePath().c_str(),0600)==0, "Cannot create FIFO fixture");
    check(!respond(), "FIFO challenge accepted");
#endif
    std::filesystem::remove(challenge.filePath());
    std::filesystem::create_directory(challenge.filePath());
    check(!respond(), "Directory challenge accepted");
    std::filesystem::remove(challenge.filePath());
    server.cancelChallenge(challenge.id());
    server.setChallengeDirectory(directory.path/"missing");
    auto failure=server.createChallenge(user);
    check(failure.error()==AuthError::IoError&&bool(failure.systemError()), "Missing-directory diagnostic lost");
#if defined(__linux__)
    auto bytes=Detail::linuxAcl(0x12345678);
    check(bytes[0]==2&&bytes[16]==0x78&&bytes[17]==0x56&&bytes[18]==0x34&&bytes[19]==0x12,
          "Linux ACL is not encoded little-endian");
#endif
}

void lifecycleTests() {
    using namespace LocalAuth;
    TemporaryDirectory directory;
    const auto user=currentUser();
    AuthServer server;AuthClient client;
    server.setChallengeDirectory(directory.path);client.setChallengeDirectory(directory.path);
    server.setChallengeTimeout(std::chrono::seconds(1));
    auto expired=server.createChallenge(user),swept=server.createChallenge(user);
    check(bool(expired)&&bool(swept), "Expiry fixtures failed");
    auto response=client.createResponse(expired.id(),expired.filePath(),expired.nonce());
    check(bool(response), "Expiry response failed");
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    check(server.verifyResponse(expired.id(),response.digest()).error()==AuthError::ChallengeExpired, "Expired response accepted");
    server.clearExpiredChallenges();
    check(!std::filesystem::exists(expired.filePath())&&!std::filesystem::exists(swept.filePath()), "Expired files remain");
    server.setChallengeTimeout(std::chrono::seconds(30));
    std::atomic<int> failures{0};
    {
        std::vector<std::thread> threads;
        Detail::ScopeExit join([&] { for(auto& thread:threads)thread.join(); });
        for(int i=0;i<8;++i)threads.emplace_back([&] {
            try {
                for(int j=0;j<8;++j) {
                    auto c=server.createChallenge(user);
                    if(!c){++failures;continue;}
                    auto r=client.createResponse(c.id(),c.filePath(),c.nonce());
                    if(!r||!server.verifyResponse(c.id(),r.digest()))++failures;
                }
            } catch(...) { ++failures; }
        });
    }
    check(failures==0, "Concurrent authentication failed");
    auto c=server.createChallenge(user);
    check(bool(c), "Replay race fixture failed");
    auto r=client.createResponse(c.id(),c.filePath(),c.nonce());
    check(bool(r), "Replay race response failed");
    std::atomic<int> successes{0};
    {
        std::vector<std::thread> threads;
        Detail::ScopeExit join([&] { for(auto& thread:threads)thread.join(); });
        for(int i=0;i<8;++i)threads.emplace_back([&] { if(server.verifyResponse(c.id(),r.digest()))++successes; });
    }
    check(successes==1, "Concurrent replay was not consumed exactly once");
    check(std::filesystem::is_empty(directory.path), "Concurrent tests left challenge files");
}

int crossAccountTests() {
#if defined(_WIN32)
    std::cout << "SKIP: cross-account test requires POSIX credential switching\n";
    return 77;
#else
    if(geteuid()!=0) {
        std::cout << "SKIP: run cross-account suite as root to drop child credentials\n";
        return 77;
    }
    using namespace LocalAuth;
    const auto owner=currentUser();
    auto* pw=getpwnam("nobody");
    check(pw&&pw->pw_uid!=0, "Missing unprivileged nobody account");
    const uid_t targetUid=pw->pw_uid;const gid_t targetGid=pw->pw_gid;
    TemporaryDirectory directory(Detail::defaultDirectory());
    check(chmod(directory.path.c_str(),0711)==0, "Cannot enable test directory traversal");
    AuthServer server;server.setChallengeDirectory(directory.path);
    auto allowed=server.createChallenge("nobody"),denied=server.createChallenge(owner),replaced=server.createChallenge("nobody");
    check(bool(allowed)&&bool(denied)&&bool(replaced), "Cross-account fixture creation failed");
    check(chown(replaced.filePath().c_str(),targetUid,targetGid)==0, "Cannot change replacement ownership");
    int pipeFd[2];check(pipe(pipeFd)==0, "Cannot create response pipe");
    Detail::ScopeExit closePipe([&] { close(pipeFd[0]);close(pipeFd[1]); });
    pid_t pid=fork();check(pid>=0, "Cannot fork test client");
    if(pid==0) {
        // Child uses _exit so it cannot delete the parent's challenge files.
        if(setgroups(0,nullptr)||setgid(targetGid)||setuid(targetUid))_exit(10);
        try {
            AuthClient client;client.setChallengeDirectory(directory.path);
            if(client.createResponse(allowed.id(),allowed.filePath(),allowed.nonce()))_exit(11);
            if(!client.setTrustedServer(owner))_exit(12);
            auto response=client.createResponse(allowed.id(),allowed.filePath(),allowed.nonce());
            if(!response)_exit(13);
            if(client.createResponse(replaced.id(),replaced.filePath(),replaced.nonce()))_exit(19);
            if(client.createResponse(denied.id(),denied.filePath(),denied.nonce()))_exit(14);
            // Verify actual OS denial as well as our client's policy checks.
            int fd=open(denied.filePath().c_str(),O_RDONLY);
            if(fd>=0){close(fd);_exit(15);}
            if(errno!=EACCES)_exit(16);
            if(write(pipeFd[1],response.digest().data(),response.digest().size())!=64)_exit(17);
            _exit(0);
        } catch(...) { _exit(18); }
    }
    int status=0;pid_t waited;
    do { waited=waitpid(pid,&status,0); } while(waited<0&&errno==EINTR);
    if(waited!=pid||!WIFEXITED(status)||WEXITSTATUS(status)!=0)
        throw std::runtime_error("Cross-account child failed with status "+std::to_string(status));
    std::array<char,64> digest{};
    check(read(pipeFd[0],digest.data(),digest.size())==64, "Missing child response");
    check(bool(server.verifyResponse(allowed.id(),std::string_view(digest.data(),digest.size()))), "Cross-account authentication failed");
    std::cout << "cross-account: OK\n";
    return 0;
#endif
}

void authenticationTests() {
    using namespace LocalAuth;
    TemporaryDirectory directory;
    const auto user = currentUser();
    AuthServer server;
    AuthClient client;
    server.setChallengeDirectory(directory.path);
    client.setChallengeDirectory(directory.path);
    auto challenge = server.createChallenge(user);
    check(bool(challenge), "Challenge creation failed (check filesystem ACL support)");
    auto response = client.createResponse(challenge.id(), challenge.filePath(), challenge.nonce());
    check(bool(response), "Challenge read failed");
    auto result = server.verifyResponse(challenge.id(), response.digest());
    check(bool(result) && result.userName() == user, "Authentication failed");
    check(!std::filesystem::exists(challenge.filePath()), "Verified challenge file remains");
    check(server.verifyResponse(challenge.id(), response.digest()).error() == AuthError::ChallengeNotFound, "Replay accepted");
    server.setAllowedUsers({});
    check(server.createChallenge(user).error() == AuthError::UserNotAllowed, "Empty allowlist accepted user");
    server.setAllowedUsers({user});
    challenge = server.createChallenge(user);
    check(bool(challenge), "Allowlisted user rejected");
    check(server.verifyResponse(challenge.id(), "invalid").error() == AuthError::InvalidResponse, "Malformed digest accepted");
    check(server.verifyResponse(challenge.id(), response.digest()).error() == AuthError::ChallengeNotFound, "Invalid attempt did not consume challenge");
    challenge=server.createChallenge(user);
    check(bool(challenge), "Invalid-digest fixture failed");
    check(server.verifyResponse(challenge.id(),std::string(64,'0')).error()==AuthError::InvalidResponse, "Wrong digest accepted");
    server.setMaximumChallenges(1);
    challenge = server.createChallenge(user);
    check(bool(challenge), "Challenge creation failed");
    check(server.createChallenge(user).error() == AuthError::TooManyChallenges, "Challenge limit ignored");
    server.cancelChallenge(challenge.id());
    check(!std::filesystem::exists(challenge.filePath()), "Canceled challenge file remains");
    check(server.verifyResponse(challenge.id(), response.digest()).error() == AuthError::ChallengeNotFound, "Canceled challenge accepted");
    std::filesystem::path pendingPath;
    {
        AuthServer temporary;
        temporary.setChallengeDirectory(directory.path);
        auto pending = temporary.createChallenge(user);
        check(bool(pending), "Challenge creation failed");
        pendingPath = pending.filePath();
    }
    check(!std::filesystem::exists(pendingPath), "Destructor left challenge file behind");
}
}

int main(int argc, char** argv) {
    try {
        const std::string suite = argc > 1 ? argv[1] : "all";
        check(suite == "all" || suite == "crypto" || suite == "authentication" ||
              suite == "hardening" || suite == "lifecycle" || suite == "cross-account", "Unknown test suite");
        if (suite == "cross-account") return crossAccountTests();
        if (suite == "all" || suite == "crypto") cryptoTests();
        if (suite == "all" || suite == "authentication") authenticationTests();
        if (suite == "all" || suite == "hardening") hardeningTests();
        if (suite == "all" || suite == "lifecycle") lifecycleTests();
        std::cout << suite << ": OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
