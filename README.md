# Requirements
 - Python >= 3.7
 - Go > 1.3
# Usage
 - Clone the repo ```git clone --recurse-submodules git@github.com:Scarjit/WebSecCheck.git```
 - Compile ssllabs scan (optional)
    - ```cd ssllabs-scan```
    - ```go build ssllabs-scan-v3.go```
 - Run ```main.py```

# Arguments

|Arg|Description|
|---|---|
|-o | Output file name|
|--disable-http-observatory | Disables testing using Mozilla's HTTP Observatory API|
|--disable-securityheaders | Disable testing using Scott Helme's securityheaders.com |
|--disable-ssllabs | Disable testing using Qualys SSLLabs.com |
|--generate-html | Generates HTML report |
|--generate-gfm | Generates Github Flavored Markdown report |
|< url >| url to test |

## Example:

```python main.py --generate-html --generate-gfm -o report https://github.com```
