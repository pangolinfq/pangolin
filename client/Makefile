VERSION := 0.0.3-dev
SHORTVERSION := 0.0.3

.PHONY: windows package-windows linux package-linux darwin package-darwin clean

define fpm-debian-build 
	echo "Running fpm-debian-build" && \
	PKG_ARCH=$1 && \
	VERSION=$2 && \
	WORKDIR=$$(mktemp -dt "$$(basename $$0).XXXXXXXXXX") && \
	INSTALLER_RESOURCES=./installer/linux && \
	\
	mkdir -p $$WORKDIR/usr/bin && \
	mkdir -p $$WORKDIR/usr/share/applications && \
	mkdir -p $$WORKDIR/usr/share/icons/hicolor/256x256/apps && \
	chmod -R 755 $$WORKDIR && \
	\
	cp $$INSTALLER_RESOURCES/pangolin.desktop $$WORKDIR/usr/share/applications && \
	cp $$INSTALLER_RESOURCES/pangolin_256.png $$WORKDIR/usr/share/icons/hicolor/256x256/apps/pangolin.png && \
	\
	cp pangolin $$WORKDIR/usr/bin/pangolin-bin && \
	cp $$INSTALLER_RESOURCES/pangolin.sh $$WORKDIR/usr/bin/pangolin && \
	\
	chmod -x $$WORKDIR/usr/bin/pangolin-bin && \
	chmod +x $$WORKDIR/usr/bin/pangolin && \
	\
	fpm -a $$PKG_ARCH -s dir -t deb -n pangolin -v $$VERSION -C $$WORKDIR -f usr;
endef

windows:
	GOOS=windows GOARCH=386 go build -ldflags="-w -s -H windowsgui" -a -o pangolin.exe
	
package-windows: windows
	sed "s/__VERSION__/${VERSION}/g" installer/windows/pangolin.nsi > pangolin-${VERSION}.nsi
	@echo "Please execute pangolin-${VERSION}.nsi under windows"

linux: 
	GOOS=linux GOARCH=amd64 go build -ldflags="-w -s -linkmode internal" -a -o pangolin

package-linux: linux
	$(call fpm-debian-build,"amd64","${VERSION}")

darwin:
	GOOS=darwin GOARCH=amd64 go build -ldflags="-w" -a -o pangolin_darwin_amd64

package-darwin: darwin
	rm -rf Pangolin.app
	cp -r installer/darwin/Pangolin.app.template Pangolin.app
	mkdir Pangolin.app/Contents/MacOS
	cp -r pangolin_darwin_amd64 Pangolin.app/Contents/MacOS/pangolin
	sed "s/__VERSION__/${VERSION}/g; s/__SHORTVERSION__/${SHORTVERSION}/g" installer/darwin/Pangolin.app.template/Contents/Info.plist > Pangolin.app/Contents/Info.plist
	sed "s/__VERSION__/${VERSION}/g" installer/darwin/pangolin.dmg.json > installer/darwin/pangolin-${VERSION}.dmg.json
	rm -rf pangolin-${VERSION}.dmg
	appdmg --quiet installer/darwin/pangolin-${VERSION}.dmg.json pangolin-${VERSION}.dmg
	rm -rf installer/darwin/pangolin-${VERSION}.dmg.json
	mv pangolin-${VERSION}.dmg pangolin-${VERSION}.dmg.zlib 
	hdiutil convert -quiet -format UDBZ -o pangolin-${VERSION}.dmg pangolin-${VERSION}.dmg.zlib
	rm pangolin-${VERSION}.dmg.zlib

clean:
	rm -rf pangolin pangolin.exe pangolin_darwin_amd64 Pangolin.app pangolin-${VERSION}.dmg pangolin-${VERSION}.nsi pangolin-${VERSION}-install.exe pangolin_${VERSION}_amd64.deb update_*
