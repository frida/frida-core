#!/bin/sh
sudo kextunload /Library/Extensions/FridaKernelAgent.kext &>/dev/null
sudo rm -rf /Library/Extensions/FridaKernelAgent.kext
sudo cp -a ~/Library/Developer/Xcode/DerivedData/FridaKernelAgent-eaueaeplpgvooydjbumkfbqjrobj/Build/Products/Debug/FridaKernelAgent.kext /Library/Extensions/FridaKernelAgent.kext
sudo chown -R root /Library/Extensions/FridaKernelAgent.kext
sudo chgrp -R wheel /Library/Extensions/FridaKernelAgent.kext
sudo kextload /Library/Extensions/FridaKernelAgent.kext
