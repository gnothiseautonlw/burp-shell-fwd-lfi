# Burp Extension: Shell FWD/LFI
> A shell-like environment in burpsuite
> ![Shell Demo](/demo/shell_command_injection_mode_without_config.gif)

# Installation
## Dependencies
Burpsuite needs 'jython' to run this plugin. If you haven't already installed it:
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

# Usage and principles
This article explains how to use the plugin. It will also demystify the principles and work that happens behind the scenes of this plugin:
https://docs.google.com/document/d/1Vk-CPFgylO79IJaSRq930qDs7N-rQnVHpRp2I9ooqR8/edit?usp=sharing
