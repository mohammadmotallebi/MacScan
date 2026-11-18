# App icon

- Source: "Security Antivirus" from SVG Repo — https://www.svgrepo.com/svg/260804/security-antivirus
- License: CC0 (public domain), https://www.svgrepo.com/page/licensing/#CC0
- The PNGs in `MacScan/Assets.xcassets/AppIcon.appiconset` are rendered from this SVG on a light rounded-square
  background by `render.swift`:

```sh
swiftc -O render.swift -o /tmp/render
/tmp/render security-antivirus.svg ../../MacScan/Assets.xcassets/AppIcon.appiconset --background
```
