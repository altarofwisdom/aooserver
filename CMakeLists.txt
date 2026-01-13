cmake_minimum_required(VERSION 3.15)

project(aooserver VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add JUCE via FetchContent
include(FetchContent)
FetchContent_Declare(
    juce
    GIT_REPOSITORY https://github.com/juce-framework/JUCE.git
    GIT_TAG        7.0.9 # Using a stable JUCE 7 release
)
FetchContent_MakeAvailable(juce)

# Define sources
set(AOO_SOURCES
    deps/aoo/lib/src/client.cpp
    deps/aoo/lib/src/codec_pcm.cpp
    deps/aoo/lib/src/common.cpp
    deps/aoo/lib/src/net_utils.cpp
    deps/aoo/lib/src/server.cpp
    deps/aoo/lib/src/sink.cpp
    deps/aoo/lib/src/source.cpp
    deps/aoo/lib/src/sync.cpp
    deps/aoo/lib/src/time.cpp
    deps/aoo/deps/md5/md5.c
    deps/aoo/deps/oscpack/osc/OscOutboundPacketStream.cpp
    deps/aoo/deps/oscpack/osc/OscPrintReceivedElements.cpp
    deps/aoo/deps/oscpack/osc/OscReceivedElements.cpp
    deps/aoo/deps/oscpack/osc/OscTypes.cpp
)

set(MAIN_SOURCES
    Source/Main.cpp
)

# Create executable
juce_add_console_app(aooserver
    PRODUCT_NAME "aooserver"
    COMPANY_NAME "Sonosaurus"
)

target_sources(aooserver PRIVATE
    ${AOO_SOURCES}
    ${MAIN_SOURCES}
)

target_include_directories(aooserver PRIVATE
    deps/aoo/lib
    deps/aoo/deps
)

target_compile_definitions(aooserver PRIVATE
    USE_CODEC_OPUS=0
    JUCE_WASAPI=0
    JUCE_DIRECTSOUND=0
    JUCE_ALSA=0
    JUCE_STRICT_REFCOUNTEDPOINTER=1
)

target_link_libraries(aooserver PRIVATE
    juce::juce_core
    juce::juce_events
    juce::juce_audio_basics
    juce::juce_audio_formats
    juce::juce_data_structures
    juce::juce_cryptography
    juce::juce_recommended_config_flags
    juce::juce_recommended_warning_flags
)

if(WIN32)
    target_link_libraries(aooserver PRIVATE ws2_32)
endif()
