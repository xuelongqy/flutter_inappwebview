import 'package:flutter/foundation.dart';
import 'in_app_webview/webview.dart';
import 'chrome_safari_browser/chrome_safari_browser.dart';

///Class that represents the debug logging settings used by [WebView] and [ChromeSafariBrowser].
class DebugLoggingSettings {
  ///Enables debug logging info.
  ///
  ///The default value is the same value of [kDebugMode],
  ///so it is enabled by default when the application is compiled in debug mode
  ///and disabled when it is not.
  bool enabled;

  ///Filters used to exclude some logs from logging.
  List<RegExp> excludeFilter;

  ///Max length of the log message.
  ///Set to `-1` to indicate that the log message needs to display the full content.
  ///
  ///The default value is `-1`.
  int maxLogMessageLength;

  DebugLoggingSettings({
    this.enabled = kDebugMode,
    this.excludeFilter = const [],
    this.maxLogMessageLength = -1
  });
}