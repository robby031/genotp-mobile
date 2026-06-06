ANDROID_OUT ?= genotp.aar
IOS_OUT     ?= Genotp.xcframework

ANDROID_SDK ?= $(HOME)/Library/Android/sdk
NDK_VERSION ?= $(shell ls $(ANDROID_SDK)/ndk 2>/dev/null | sort -V | tail -1)
ANDROID_NDK_HOME ?= $(ANDROID_SDK)/ndk/$(NDK_VERSION)

.PHONY: build-android build-ios init

init:
	go install golang.org/x/mobile/cmd/gomobile@latest
	gomobile init

ANDROID_API ?= 21

build-android:
	ANDROID_NDK_HOME=$(ANDROID_NDK_HOME) gomobile bind -target android -androidapi $(ANDROID_API) -o $(ANDROID_OUT) .

build-ios:
	gomobile bind -target ios -o $(IOS_OUT) .
