find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets Svg)
qt_standard_project_setup()
set(CMAKE_AUTORCC ON)

qt_add_executable(encpto WIN32 MACOSX_BUNDLE
    main.cpp
    MainWindow.cpp MainWindow.hpp
    Widgets.cpp Widgets.hpp
    Task.cpp Task.hpp
    Theme.cpp Theme.hpp
    I18n.cpp I18n.hpp
    Prefs.cpp Prefs.hpp
    resources/resources.qrc
)

target_link_libraries(encpto PRIVATE encpto::core Qt6::Widgets Qt6::Svg)
encpto_set_warnings(encpto)

if(WIN32)
    set(rc ${CMAKE_CURRENT_BINARY_DIR}/encpto.rc)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/resources/app-icon.ico" ico)
    string(REPLACE "\\" "\\\\" ico "${ico}")
    file(WRITE ${rc} "IDI_ICON1 ICON \"${ico}\"\n")
    target_sources(encpto PRIVATE ${rc})
    set_target_properties(encpto PROPERTIES OUTPUT_NAME "enCPTO")
elseif(APPLE)
    set(MACOSX_BUNDLE_ICON_FILE app-icon.icns)
    set(icns ${CMAKE_CURRENT_SOURCE_DIR}/resources/app-icon.icns)
    set_source_files_properties(${icns} PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
    target_sources(encpto PRIVATE ${icns})
    set_target_properties(encpto PROPERTIES
        OUTPUT_NAME "enCPTO"
        MACOSX_BUNDLE_BUNDLE_NAME "enCPTO"
        MACOSX_BUNDLE_GUI_IDENTIFIER "io.github.nil-coder-sudo.encpto"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
        MACOSX_BUNDLE_COPYRIGHT "MIT License")
endif()

install(TARGETS encpto
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION bin)

if(UNIX AND NOT APPLE)
    install(FILES resources/encpto.desktop DESTINATION share/applications)
    install(FILES resources/app-icon.svg DESTINATION share/icons/hicolor/scalable/apps RENAME encpto.svg)
endif()
