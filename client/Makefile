VERSION := 0.0.1-dev
SHORTVERSION := 0.0.1

.PHONY: windows linux darwin package-darwin clean

windows:
	GOOS=windows GOARCH=386 go build -ldflags="-w -s -H windowsgui" -a -o pangolin.exe

linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-w -s -linkmode internal" -a -o pangolin

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
	rm -rf pangolin pangolin.exe pangolin_darwin_amd64 Pangolin.app pangolin-${VERSION}.dmg
