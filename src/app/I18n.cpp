#include "I18n.hpp"

#include <QHash>
#include <utility>

namespace i18n {
namespace {

Lang g_lang = Lang::ZhTW;

using Pair = std::pair<const char*, const char*>;  // zh-TW, English

const QHash<QString, Pair>& table() {
    static const QHash<QString, Pair> strings = {
        // ── Chrome ────────────────────────────────────────────────────
        {"window_title", {"enCPTO — 檔案與資料夾加密", "enCPTO — file & folder encryption"}},
        {"tab_main", {"加密與解密", "Encrypt and decrypt"}},
        {"tab_generator", {"密碼產生器", "Password generator"}},
        {"tab_settings", {"設定", "Settings"}},
        {"switch_language", {"English", "中文"}},
        {"switch_language_tip", {"Switch to English", "切換為繁體中文"}},

        // ── Source / drop zone ────────────────────────────────────────
        {"drop_title", {"把檔案或資料夾拖到這裡", "Drop a file or folder here"}},
        {"drop_subtitle", {"任何檔案或資料夾都能加密；放入 .dat 加密檔則可解密",
                           "Encrypt any file or folder, or drop a .dat container to decrypt it"}},
        {"drop_release", {"放開以載入", "Release to load"}},
        {"choose_file", {"選擇檔案", "Choose file"}},
        {"choose_folder", {"選擇資料夾", "Choose folder"}},
        {"remove_source", {"移除", "Remove"}},
        {"meta_file", {"檔案，%1", "File, %1"}},
        {"meta_folder", {"資料夾，%1 個檔案，共 %2", "Folder, %1 files, %2 in total"}},
        {"meta_container", {"enCPTO 加密檔，%1", "enCPTO container, %1"}},
        {"preview_v7", {"原始檔名與類型都已加密。\n輸入密碼後按「解密」即可還原。",
                        "The original name and type are encrypted.\nEnter the password and press Decrypt to restore it."}},
        {"preview_legacy", {"這是舊版 V%1 加密檔，新版只支援 V7。\n請用 legacy/enCPTO-v7.py 解密一次，再用新版重新加密。",
                            "This is a legacy V%1 container; this version reads V7 only.\nDecrypt it once with legacy/enCPTO-v7.py, then re-encrypt it here."}},
        {"preview_folder", {"整個資料夾會在記憶體中打包後加密，\n未加密的內容不會寫到磁碟。",
                            "The whole folder is packed in memory and encrypted;\nunencrypted data is never written to disk."}},
        {"preview_none", {"這種檔案無法預覽", "No preview for this type of file"}},
        {"preview_truncated", {"\n\n…（只顯示前 50 KB）", "\n\n… (first 50 KB shown)"}},

        // ── Key column ────────────────────────────────────────────────
        {"password", {"密碼", "Password"}},
        {"password_placeholder", {"輸入密碼", "Enter a password"}},
        {"show_password", {"顯示密碼", "Show password"}},
        {"hide_password", {"隱藏密碼", "Hide password"}},
        {"generate_password", {"產生強密碼", "Generate a strong password"}},
        {"strength_empty", {"至少 8 個字元，並包含大寫、小寫、數字、符號其中三種",
                            "At least 8 characters, using 3 of: uppercase, lowercase, digits, symbols"}},
        {"strength_short", {"太短：至少需要 8 個字元", "Too short: use at least 8 characters"}},
        {"strength_weak", {"太弱：再加入大寫、數字或符號", "Too weak: add uppercase letters, digits or symbols"}},
        {"strength_fair", {"可以使用；更長會更安全", "Acceptable; a longer password is safer"}},
        {"strength_good", {"強", "Strong"}},
        {"strength_excellent", {"非常強", "Very strong"}},
        {"strength_bits", {"約 %1 位元", "about %1 bits"}},
        {"decrypt_hint", {"解密時只需要輸入加密當時的密碼。", "To decrypt, enter the password used to encrypt."}},
        {"shred_option", {"加密後粉碎原始檔案", "Shred the original after encrypting"}},
        {"shred_hint", {"覆寫三次後刪除，無法復原。SSD 上無法保證完全清除。",
                        "Overwritten three times, then deleted. Cannot be undone; SSDs may keep old copies."}},
        {"encrypt", {"加密", "Encrypt"}},
        {"decrypt", {"解密", "Decrypt"}},
        {"cancel", {"取消", "Cancel"}},
        {"show_in_folder", {"在資料夾中顯示", "Show in folder"}},
        {"no_password_recovery", {"密碼是唯一的鑰匙，忘記就無法還原。", "The password is the only key. If you forget it, the data cannot be recovered."}},

        // ── Status ────────────────────────────────────────────────────
        {"status_ready", {"就緒", "Ready"}},
        {"phase_kdf", {"推導金鑰（Argon2id）", "Deriving key (Argon2id)"}},
        {"phase_pack", {"打包資料夾", "Packing folder"}},
        {"phase_encrypt", {"加密中", "Encrypting"}},
        {"phase_verify", {"驗證完整性", "Verifying integrity"}},
        {"phase_decrypt", {"解密中", "Decrypting"}},
        {"phase_extract", {"還原資料夾", "Restoring folder"}},
        {"phase_shred", {"粉碎原始檔", "Shredding original"}},
        {"done_encrypt", {"已加密：%1", "Encrypted: %1"}},
        {"done_encrypt_shred", {"已加密並粉碎原始檔：%1", "Encrypted and shredded the original: %1"}},
        {"done_decrypt", {"已還原：%1", "Restored: %1"}},
        {"done_time", {"（%1 秒）", " (%1 s)"}},
        {"cancelled", {"已取消，沒有留下不完整的檔案。", "Cancelled. No partial files were left behind."}},

        // ── Dialogs & errors ──────────────────────────────────────────
        {"err_title", {"無法完成", "Couldn't finish"}},
        {"err_no_source", {"請先選擇檔案或資料夾。", "Choose a file or folder first."}},
        {"err_weak_password", {"密碼不符合要求：至少 8 個字元，並包含大寫、小寫、數字、符號其中三種。",
                               "The password is too weak: use at least 8 characters with 3 of uppercase, lowercase, digits and symbols."}},
        {"err_no_password", {"請輸入密碼。", "Enter the password."}},
        {"err_not_container", {"這不是 enCPTO 加密檔，無法解密。", "This is not an enCPTO container, so it can't be decrypted."}},
        {"err_wrong_password", {"密碼錯誤，或檔案已被修改。", "Wrong password, or the file was modified."}},
        {"err_tampered", {"完整性驗證失敗：檔案已被修改或損毀。沒有寫出任何資料。",
                          "Integrity check failed: the file was modified or is damaged. Nothing was written."}},
        {"err_corrupted", {"檔案已損毀或不完整。", "The file is damaged or incomplete."}},
        {"confirm_shred_title", {"要粉碎原始檔案嗎？", "Shred the original?"}},
        {"confirm_shred_body", {"加密完成後，「%1」會被覆寫三次並刪除，無法復原。",
                                "After encryption, “%1” will be overwritten three times and deleted. This cannot be undone."}},
        {"confirm_shred_button", {"加密並粉碎", "Encrypt and shred"}},
        {"save_dialog", {"儲存加密檔", "Save encrypted file"}},
        {"restore_dialog", {"選擇還原位置", "Choose where to restore"}},
        {"choose_file_dialog", {"選擇要加密或解密的檔案", "Choose a file to encrypt or decrypt"}},
        {"choose_folder_dialog", {"選擇要加密的資料夾", "Choose a folder to encrypt"}},
        {"quit_busy_title", {"作業仍在進行", "Still working"}},
        {"quit_busy_body", {"要取消目前的作業並關閉嗎？", "Cancel the current operation and quit?"}},

        // ── Generator ─────────────────────────────────────────────────
        {"gen_heading", {"產生強密碼", "Generate a strong password"}},
        {"gen_intro", {"使用作業系統的安全亂數來源，每種勾選的字元至少出現一次。",
                       "Uses your operating system's secure random source; every selected set appears at least once."}},
        {"gen_length", {"長度：%1 個字元", "Length: %1 characters"}},
        {"gen_upper", {"大寫字母 A–Z", "Uppercase A–Z"}},
        {"gen_lower", {"小寫字母 a–z", "Lowercase a–z"}},
        {"gen_digits", {"數字 0–9", "Digits 0–9"}},
        {"gen_symbols", {"符號 !#$%…", "Symbols !#$%…"}},
        {"gen_ambiguous", {"排除容易看錯的字元（0 O 1 l I）", "Leave out look-alike characters (0 O 1 l I)"}},
        {"gen_new", {"產生新密碼", "Generate"}},
        {"gen_copy", {"複製", "Copy"}},
        {"gen_use", {"填入密碼欄", "Use this password"}},
        {"gen_copied", {"已複製，30 秒後自動清除剪貼簿。", "Copied. The clipboard is cleared after 30 seconds."}},
        {"gen_used", {"已填入加密頁的密碼欄。", "Filled in on the encrypt page."}},
        {"gen_need_set", {"請至少勾選一種字元。", "Select at least one character set."}},

        // ── Settings ──────────────────────────────────────────────────
        {"set_appearance", {"外觀", "Appearance"}},
        {"set_theme", {"主題", "Theme"}},
        {"theme_Dark", {"藍圖（深色）", "Blueprint (dark)"}},
        {"theme_Light", {"製圖紙（淺色）", "Drafting paper (light)"}},
        {"theme_System", {"跟隨系統", "Follow system"}},
        {"theme_Auto", {"依時間自動切換", "Automatic by time of day"}},
        {"theme_Army Green", {"軍綠", "Army green"}},
        {"theme_Deep Hacker", {"終端機綠", "Terminal green"}},
        {"set_background", {"背景圖片", "Background image"}},
        {"set_background_none", {"沒有背景圖片", "No background image"}},
        {"set_background_choose", {"選擇圖片", "Choose image"}},
        {"set_background_clear", {"清除", "Clear"}},
        {"set_overlay", {"背景遮罩：%1%", "Background overlay: %1%"}},
        {"set_overlay_hint", {"0% 完整顯示圖片，100% 只顯示主題色", "0% shows the full image, 100% shows only the theme colour"}},
        {"set_panel_opacity", {"面板不透明度：%1%", "Panel opacity: %1%"}},
        {"set_panel_opacity_hint", {"使用背景圖片時，建議 70–90%", "With a background image, 70–90% reads best"}},
        {"set_performance", {"效能", "Performance"}},
        {"set_threads", {"加密執行緒", "Encryption threads"}},
        {"set_threads_auto", {"自動（%1 個）", "Automatic (%1)"}},
        {"set_threads_hint", {"區塊會分配到多個 CPU 核心同時加解密。", "Chunks are encrypted and decrypted on several CPU cores at once."}},
        {"set_about", {"關於", "About"}},
        {"set_about_body", {
            "enCPTO %1，加密格式 V7（可解開 v7.0 Python 版建立的檔案）\n\n"
            "金鑰：Argon2id（t=4、256 MiB、p=4）＋ HKDF-SHA512\n"
            "第一層：AES-256-CTR　第二層：XChaCha20-Poly1305\n"
            "整體驗證：HMAC-SHA512，驗證通過才寫出任何明文",
            "enCPTO %1, container format V7 (reads files made by the v7.0 Python tool)\n\n"
            "Key: Argon2id (t=4, 256 MiB, p=4) + HKDF-SHA512\n"
            "Layer 1: AES-256-CTR    Layer 2: XChaCha20-Poly1305\n"
            "Whole-file check: HMAC-SHA512, verified before any plaintext is written"}},
        {"set_source_link", {"原始碼與說明", "Source code and documentation"}},

        // ── Experimental ──────────────────────────────────────────────
        {"set_experimental", {"實驗性功能", "Experimental"}},
        {"gpu_enable", {"使用 GPU 加速（OpenCL）", "Use GPU acceleration (OpenCL)"}},
        {"gpu_device", {"裝置", "Device"}},
        {"gpu_kind_gpu", {"顯示卡", "GPU"}},
        {"gpu_kind_cpu", {"CPU", "CPU"}},
        {"gpu_no_runtime", {"找不到 OpenCL 執行環境，請安裝或更新顯示卡驅動程式。", "No OpenCL runtime found. Install or update your graphics driver."}},
        {"gpu_no_device", {"已安裝 OpenCL，但找不到可用的裝置。", "OpenCL is installed, but no usable device was found."}},
        {"gpu_warning", {
            "加密時金鑰與資料會經過顯示卡記憶體，那裡無法鎖定，也不保證會被清除；enCPTO 用完會主動歸零。"
            "產生的加密檔和 CPU 完全相同。多數電腦整體不會變快，原因請看下方測速結果。",
            "Keys and data pass through graphics memory, which can't be locked and isn't guaranteed to be cleared; "
            "enCPTO zeroes it after use. Encrypted files are identical to the CPU path. "
            "Most computers won't get faster overall — run the benchmark below to see why."}},
        {"bench_title", {"測速", "Benchmark"}},
        {"bench_intro", {"測量這台電腦每個環節的速度，找出限制整體速度的瓶頸。約需 10 秒，期間會用滿 CPU。",
                         "Measures every stage on this computer and finds what limits overall speed. Takes about 10 seconds at full CPU load."}},
        {"bench_run", {"開始測速", "Run benchmark"}},
        {"bench_running", {"測速中… %1/%2", "Measuring… %1/%2"}},
        {"bench_argon2", {"Argon2id 金鑰推導", "Argon2id key derivation"}},
        {"bench_aes", {"AES-256-CTR（1 核心）", "AES-256-CTR (1 core)"}},
        {"bench_chacha", {"XChaCha20-Poly1305（1 核心）", "XChaCha20-Poly1305 (1 core)"}},
        {"bench_hmac", {"HMAC-SHA512（只能依序）", "HMAC-SHA512 (sequential)"}},
        {"bench_layers_cpu", {"兩層加密（所有核心）", "Both layers (all cores)"}},
        {"bench_layers_gpu", {"兩層加密（GPU）", "Both layers (GPU)"}},
        {"bench_pipe_cpu", {"完整加密流程（CPU）", "Full pipeline (CPU)"}},
        {"bench_pipe_gpu", {"完整加密流程（GPU）", "Full pipeline (GPU)"}},
        {"bench_seconds", {"每個檔案 %1 秒（刻意的固定成本）", "%1 s per file (deliberate fixed cost)"}},
        {"bench_bottleneck", {"瓶頸", "Bottleneck"}},
        {"bench_summary_hmac", {
            "瓶頸是 HMAC-SHA512：它必須從頭到尾依序計算，只能用一個核心，所以加密層再快，整體也很難超過約 %1 MiB/s。",
            "The bottleneck is HMAC-SHA512: it runs in order on a single core, so however fast the cipher layers are, the total stays near %1 MiB/s."}},
        {"bench_summary_layers", {"瓶頸是加密層本身，增加執行緒或改用 GPU 可能有幫助。",
                                  "The cipher layers are the bottleneck; more threads or the GPU may help."}},
        {"bench_details", {"以 %1 個執行緒、每項 %2 MiB 測得。", "Measured with %1 threads, %2 MiB per stage."}},
        {"bench_gpu_used", {"GPU：%1", "GPU: %1"}},
        {"bench_gpu_skipped", {"GPU 項目已略過：%1", "GPU stages skipped: %1"}},
        {"bench_gpu_hint", {"在上方勾選 GPU 加速，就會一起測量 GPU。", "Tick GPU acceleration above to include the GPU."}},
        {"phase_gpu", {"（GPU）", " (GPU)"}},
        {"err_gpu", {"GPU 加速失敗。請到「設定 → 實驗性功能」關閉後再試一次。\n\n%1",
                     "GPU acceleration failed. Turn it off under Settings → Experimental and try again.\n\n%1"}},
    };
    return strings;
}

}  // namespace

void setLanguage(Lang lang) { g_lang = lang; }
Lang language() { return g_lang; }

Lang fromCode(const QString& code) {
    return code.compare(QLatin1String("EN"), Qt::CaseInsensitive) == 0 ? Lang::En : Lang::ZhTW;
}

QString code(Lang lang) { return lang == Lang::En ? QStringLiteral("EN") : QStringLiteral("TW"); }

QString t(const char* key) {
    const auto it = table().constFind(QString::fromUtf8(key));
    if (it == table().constEnd()) {
        return QString::fromUtf8(key);
    }
    return QString::fromUtf8(g_lang == Lang::En ? it->second : it->first);
}

}  // namespace i18n
