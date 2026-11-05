#pragma once

#include <QString>

/// Bilingual UI strings (繁體中文 / English).
namespace i18n {

enum class Lang { ZhTW, En };

void setLanguage(Lang lang);
Lang language();
Lang fromCode(const QString& code);  // "TW" / "EN"
QString code(Lang lang);

/// Looks up `key`; unknown keys are returned verbatim so gaps are visible.
QString t(const char* key);

template <typename... Args>
QString t(const char* key, const Args&... args) {
    return t(key).arg(args...);
}

}  // namespace i18n

using i18n::t;
