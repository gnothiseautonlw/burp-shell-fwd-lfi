# Burp Extension: Shell FWD/FLI
> A shell-like environment in burpsuite
> ![Shell Demo](/demo/shell_command_injection_mode_without_config.gif)

# Installation
## Dependencies
> Burpsuite needs 'jython' to run this plugin. If you haven't already installed it:
```
cd /opt
sudo mkdir jython
sudo cd jython
wget https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.2/jython-standalone-2.7.2.jar
```
(or visit https://www.jython.org/download.html and download manual)

## Dependencies configuration
Open Burpsuite
   * In the 'Extender'-tab, click the 'options' tab
      * In the section 'Python Environment'
         * Click 'Select file'
         * Navigate to /opt/jython
         * Select 'jython-standalone-2.7.2.jar'
         * And click 'open'

## Plugin installation
```
cd /opt
git clone https://github.com/gnothiseautonlw/burp-shell-fwd-lfi.git
```

## Add plugin to Burpsuite
Open Burpsuite
  * In the 'Extender'-tab, with the 'Extensions' tab selected
    * Click the 'Add'-button
      * Select 'Python' as Extension type
      * Click 'Select file...'
      * Navigate to '/opt/burp-shell-fwd-lfi/
      * Select 'shell.py'
      * Click 'next'
