ANDROID_OUT ?= genotp.aar
IOS_OUT     ?= Genotp.xcframework
IOS_ZIP_OUT ?= Genotp.xcframework.zip
SOURCE_JAR  ?= genotp-sources.jar

ANDROID_SDK ?= $(HOME)/Library/Android/sdk
NDK_VERSION ?= $(shell ls $(ANDROID_SDK)/ndk 2>/dev/null | sort -V | tail -1)
ANDROID_NDK_HOME ?= $(ANDROID_SDK)/ndk/$(NDK_VERSION)
X_MOBILE_VERSION ?= $(shell go list -m -f '{{.Version}}' golang.org/x/mobile)
ANDROID_EXT_LDFLAGS ?= -Wl,-z,max-page-size=16384

.PHONY: init build-android verify-android-elf build-ios build-all package-ios build-source-jar checksums clean

init:
	go install golang.org/x/mobile/cmd/gomobile@$(X_MOBILE_VERSION)
	gomobile init

ANDROID_API ?= 21

build-android:
	ANDROID_NDK_HOME=$(ANDROID_NDK_HOME) gomobile bind -target android -androidapi $(ANDROID_API) -ldflags='-extldflags=$(ANDROID_EXT_LDFLAGS)' -o $(ANDROID_OUT) .

verify-android-elf:
	@tmpdir=$$(mktemp -d); \
	unzip -oq $(ANDROID_OUT) -d $$tmpdir; \
	for so in $$tmpdir/jni/*/libgojni.so; do \
		echo "Checking $$so"; \
		llvm-readelf -l $$so | awk '/LOAD/{getline; if ($$NF != "0x4000") { print "Invalid alignment for " FILENAME ": " $$NF; exit 1 }}'; \
	done; \
	rm -rf $$tmpdir

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
