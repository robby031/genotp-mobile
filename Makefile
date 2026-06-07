ANDROID_OUT ?= genotp.aar
IOS_OUT     ?= Genotp.xcframework
IOS_ZIP_OUT ?= Genotp.xcframework.zip
SOURCE_JAR  ?= genotp-sources.jar

ANDROID_SDK ?= $(HOME)/Library/Android/sdk
NDK_VERSION ?= $(shell ls $(ANDROID_SDK)/ndk 2>/dev/null | sort -V | tail -1)
ANDROID_NDK_HOME ?= $(ANDROID_SDK)/ndk/$(NDK_VERSION)
X_MOBILE_VERSION ?= $(shell go list -m -f '{{.Version}}' golang.org/x/mobile)

.PHONY: init build-android build-ios build-all package-ios build-source-jar checksums clean

init:
	go install golang.org/x/mobile/cmd/gomobile@$(X_MOBILE_VERSION)
	gomobile init

ANDROID_API ?= 21

build-android:
	ANDROID_NDK_HOME=$(ANDROID_NDK_HOME) gomobile bind -target android -androidapi $(ANDROID_API) -o $(ANDROID_OUT) .

build-ios:
	gomobile bind -target ios -o $(IOS_OUT) .

build-all: build-android build-ios

package-ios:
	rm -f $(IOS_ZIP_OUT)
	ditto -c -k --sequesterRsrc --keepParent $(IOS_OUT) $(IOS_ZIP_OUT)

build-source-jar:
	rm -f $(SOURCE_JAR)
	jar --create --file $(SOURCE_JAR) mobile.go

checksums:
	shasum -a 256 $(ANDROID_OUT) $(IOS_ZIP_OUT) $(SOURCE_JAR) > SHA256SUMS

clean:
	rm -rf $(ANDROID_OUT) $(IOS_OUT) $(IOS_ZIP_OUT) $(SOURCE_JAR) SHA256SUMS
