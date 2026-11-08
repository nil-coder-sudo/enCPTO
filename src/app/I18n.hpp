#pragma once

#include <QString>

#include <type_traits>

/// Bilingual UI strings (繁體中文 / English).
namespace i18n {

enum class Lang { ZhTW, En };

void setLanguage(Lang lang);
Lang language();
Lang fromCode(const QString& code);  // "TW" / "EN"
QString code(Lang lang);

/// Looks up `key`; unknown keys are returned verbatim so gaps are visible.
QString t(const char* key);

inline QString argText(const QString& s) { return s; }
inline QString argText(const char* s) { return QString::fromUtf8(s); }
template <typename T>
    requires std::is_arithmetic_v<T>
QString argText(T v) {
    return QString::number(v);
}

/// Every argument is converted to text first: QString::arg(int, int) would
/// otherwise read the second number as a field width.
template <typename... Args>
QString t(const char* key, const Args&... args) {
    return t(key).arg(argText(args)...);
}

}  // namespace i18n

using i18n::t;
