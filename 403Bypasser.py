from burp import IBurpExtender, IScanIssue, IScannerCheck, IContextMenuFactory, IContextMenuInvocation, ITab
from javax.swing import JMenuItem
from javax import swing
from javax.swing import JPanel, JButton, JList, JTable, table, JLabel, JScrollPane, JTextField, WindowConstants, GroupLayout, LayoutStyle, JFrame
from java.awt import BorderLayout
import java.util.ArrayList as ArrayList
import java.lang.String as String
from java.lang import Short

import thread

queryPayloadsFile = open('query payloads.txt', "r")
queryPayloadsFromFile = queryPayloadsFile.readlines()

extentionName = "403 Bypasser"
requestNum = 2

class uiTab(JFrame):

	def queryAddButtonClicked(self, event):
		textFieldValue = self.queryPayloadsAddPayloadTextField.getText()

		if textFieldValue != "":
			tableModel = self.queryPayloadsTable.getModel()
			tableModel.addRow([textFieldValue])
		self.queryPayloadsAddPayloadTextField.setText("")

	def queryClearButtonClicked(self, event):
		global requestNum
		requestNum = 2
		tableModel = self.queryPayloadsTable.getModel()
		tableModel.setRowCount(0)

	def queryRemoveButtonClicked(self, event):
		tableModel = self.queryPayloadsTable.getModel()
		selectedRows = self.queryPayloadsTable.getSelectedRows()
		for row in selectedRows:
			tableModel.removeRow(row)
		global requestNum
		if requestNum > 2:
			requestNum -= 1

	def __init__(self):
		self.queryPayloadsLabel = JLabel()
		self.jScrollPane1 = JScrollPane()
		self.queryPayloadsTable = JTable()
		self.queryPayloadsAddPayloadTextField = JTextField()
		self.queryPayloadsAddButton = JButton("Add", actionPerformed=self.queryAddButtonClicked)
		self.queryPayloadsClearButton = JButton("Clear", actionPerformed=self.queryClearButtonClicked)
		self.queryPayloadsRemoveButton = JButton("Remove", actionPerformed=self.queryRemoveButtonClicked)

		self.panel = JPanel()

		self.queryPayloadsLabel.setText("Query Payloads")

		queryTableData = []
		for queryPayload in queryPayloadsFromFile:
			queryTableData.append([queryPayload])

		queryTableColumns = [None]
		queryTableModel = table.DefaultTableModel(queryTableData,queryTableColumns)
		self.queryPayloadsTable.setModel(queryTableModel)

		self.jScrollPane1.setViewportView(self.queryPayloadsTable)

		self.jScrollPane1.setViewportView(self.queryPayloadsTable)

		layout = GroupLayout(self.panel)
		self.panel.setLayout(layout)

		
		layout.setHorizontalGroup(
			layout.createParallelGroup(GroupLayout.Alignment.LEADING)
			.addGroup(layout.createSequentialGroup()
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
					.addComponent(self.queryPayloadsAddButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(self.queryPayloadsRemoveButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(self.queryPayloadsClearButton, GroupLayout.PREFERRED_SIZE, 93, GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
					.addComponent(self.queryPayloadsLabel)
					.addComponent(self.queryPayloadsAddPayloadTextField)
					.addComponent(self.jScrollPane1, GroupLayout.PREFERRED_SIZE, 107, GroupLayout.PREFERRED_SIZE))
				.addGap(100, 100, 100)
				.addGap(0, 483, Short.MAX_VALUE))
		)
		layout.setVerticalGroup(
			layout.createParallelGroup(GroupLayout.Alignment.LEADING)
			.addGroup(layout.createSequentialGroup()
				.addGap(17, 17, 17)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
					.addGroup(layout.createSequentialGroup()
						.addComponent(self.queryPayloadsLabel)
						.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
						.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
							.addComponent(self.jScrollPane1, GroupLayout.PREFERRED_SIZE, 195, GroupLayout.PREFERRED_SIZE)
							.addGroup(layout.createSequentialGroup()
								.addComponent(self.queryPayloadsClearButton)
								.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(self.queryPayloadsRemoveButton)))
						.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
						.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
							.addComponent(self.queryPayloadsAddPayloadTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
							.addComponent(self.queryPayloadsAddButton))))
				.addContainerGap(324, Short.MAX_VALUE))
		)



class BurpExtender(IBurpExtender, IScannerCheck, IContextMenuFactory, ITab):
	def registerExtenderCallbacks(self, callbacks):
		self.callbacks = callbacks
		self.helpers = self.callbacks.getHelpers()
		self.callbacks.registerScannerCheck(self)
		self.callbacks.registerContextMenuFactory(self)
		self.callbacks.setExtensionName(extentionName)

		self.callbacks.addSuiteTab(self)

		sys.stdout = self.callbacks.getStdout()
		sys.stderr = self.callbacks.getStderr()
		
		return None

	def getTabCaption(self):
		return extentionName

	def getUiComponent(self):
		self.frm = uiTab()

		return self.frm.panel

	def createMenuItems(self, invocation):
		self.context = invocation
		self.menuList = []
		self.menuItem = JMenuItem("Bypass 403", actionPerformed=self.testFromMenu)
		self.menuList.append(self.menuItem)
		return self.menuList

	def testFromMenu(self, event):
		selectedMessages = self.context.getSelectedMessages()
		for message in selectedMessages:
			thread.start_new_thread(self.doActiveScan, (message, "" , True, ))

		return None


	def isInteresting(self, response):
		responseCode = response.getStatusCode()
		if responseCode == 403:
			return True
		else:
			return False

	def findAllCharIndexesInString(self,s, ch):
		return [i for i, ltr in enumerate(s) if ltr == ch]

	def generatePayloadsFromFile(self, path, payload):
		payloads = []

		#generate payloads before slash
		for i in self.findAllCharIndexesInString(path, "/"):
			pathWithPayload = path[:i] + payload + path[i:]
			payloads.append(pathWithPayload)

		#generate payloads after slash
		for i in self.findAllCharIndexesInString(path, "/"):
			pathWithPayload = path[:i] + "/" + payload + path[i+1:]
			payloads.append(pathWithPayload)

		#generate payloads in between slashes
		for i in self.findAllCharIndexesInString(path, "/"):
			pathWithPayload = path[:i] + "/" + payload + "/" + path[i+1:]
			payloads.append(pathWithPayload)

		#generate payloads at the end of the path
		payloads.append(path + "/" + payload)
		payloads.append(path + "/" + payload + "/")

		return payloads

	def generateAdditionalPayloads(self, path, payloads):
		payloads = []
		# URL encode slashes
		payloads.append(path.replace("/", "%2F"))

		# Double URL encode slashes
		payloads.append(path.replace("/", "%252F"))

		# URL encode the first character of each path segment
		for i in self.findAllCharIndexesInString(path, "/"):
			pathWithPayload = path[:i] + "/%{0:0>2x}".format(ord(path[i+1])) + path[i+2:]
			payloads.append(pathWithPayload)

		# URL encode the last character of each path segment
		for i in self.findAllCharIndexesInString(path, "/")[1:]:
			pathWithPayload = path[:i-1] + "%{0:0>2x}".format(ord(path[i-1])) + "/" + path[i+1:]
			payloads.append(pathWithPayload)

		payloads.append(path[:-1] + "%{0:0>2x}".format(ord(path[-1])))

		# # Double URL encode first character of each path segment
		for i in self.findAllCharIndexesInString(path, "/"):
			pathWithPayload = path[:i] + "/%25{0:0>2x}".format(ord(path[i+1])) + path[i+2:]
			payloads.append(pathWithPayload)

		# # Double URL encode last character of each path segment
		for i in self.findAllCharIndexesInString(path, "/")[1:]:
			pathWithPayload = path[:i-1] + "%25{0:0>2x}".format(ord(path[i-1])) + "/" + path[i+1:]
			payloads.append(pathWithPayload)

		payloads.append(path[:-1] + "%25{0:0>2x}".format(ord(path[-1])))
		
		# some normalization thing with %ef%bc%8f - this should be some / equivalent ...
		for i in self.findAllCharIndexesInString(path, "/"):
			pathWithPayload = path[:i] + "%ef%bc%8f" + path[i+1:]
			payloads.append(pathWithPayload)

		payloads.append(path + "%ef%bc%8f")

		# Try adding extensions
		nPath = path
		
		withOutExtension = path.split(".")

		if withOutExtension:
			nPath = withOutExtension[0]

		ext = [".js", ".json", ".css", ".html"]

		for e in ext:
			payloads.append(nPath+e)

		# TODO: combining shit?

		return payloads

	def tryBypassWithQueryPayload(self, request, httpService, generateFunction, payload=''):
		results = []
		#each result element is an array of [detail,httpMessage]

		requestPath = request.getUrl().getPath()
		payloads = generateFunction(requestPath, payload)


		originalRequest = self.helpers.bytesToString(request.getRequest())
		for pathToTest in payloads:
			try:
				newRequest = originalRequest.replace(requestPath, pathToTest)
				newRequestResult = self.callbacks.makeHttpRequest(httpService, newRequest)
				newRequestStatusCode = str(self.helpers.analyzeResponse(newRequestResult.getResponse()).getStatusCode())
			except:
				print("No response from server")
				newRequestStatusCode = None
				pass


			if newRequestStatusCode == "200":
				originalRequestUrl = str(request.getUrl())
				vulnerableReuqestUrl = originalRequestUrl.replace(requestPath,pathToTest)

				responseHeaders = str(self.helpers.analyzeResponse(newRequestResult.getResponse()).getHeaders()).split(",")
				resultContentLength = "No CL in response"
				for header in responseHeaders:
					if "Content-Length: " in header:
						resultContentLength = header[17:]
						if resultContentLength[-1] == ']': # happens if CL header is the last header in response
							resultContentLength = resultContentLength.rstrip(']')

				issue = []
				global requestNum

				issue.append("<tr><td>" + str(requestNum) + "</td><td>" + vulnerableReuqestUrl.replace(payload, "<b>" + payload + "</b>") + "</td> <td>" + newRequestStatusCode + "</td> <td>" + resultContentLength + "</td></tr>")
				issue.append(newRequestResult)
				results.append(issue)
				requestNum += 1

		if len(results) > 0:
			return results
		else:
			return None

	def tryBypassWithPOSTAndEmptyCL(self, baseRequestResponse, httpService):
		issue = []
		requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
		headers = requestInfo.getHeaders()
		headers[0] = headers[0].replace("GET", "POST")
		headers.append("Content-Length: 0")

		headersAsJavaSublist = ArrayList()
		for header in headers:
			headersAsJavaSublist.add(String(header))

		requestBody = baseRequestResponse.getRequest()[requestInfo.getBodyOffset():]

		newRequest = self.helpers.buildHttpMessage(headersAsJavaSublist, requestBody)
		newRequestResult = self.callbacks.makeHttpRequest(httpService, newRequest)
		newRequestStatusCode = str(self.helpers.analyzeResponse(newRequestResult.getResponse()).getStatusCode())

		if newRequestStatusCode == "200":
			responseHeaders = str(self.helpers.analyzeResponse(newRequestResult.getResponse()).getHeaders()).split(",")
			requestUrl = str(baseRequestResponse.getUrl())
			resultContentLength = "No CL in response"

			for header in responseHeaders:
				if "Content-Length: " in header:
					resultContentLength = header[17:]
					if resultContentLength[-1] == ']': # happens if CL header is the last header in response
						resultContentLength = resultContentLength.rstrip(']')

			requestNum = 2
			issue.append("<tr><td>" + str(requestNum) + "</td><td>" + requestUrl + "</td> <td>" + newRequestStatusCode + "</td> <td>" + resultContentLength + "</td></tr>")
			issue.append(newRequestResult)

		if len(issue) > 0:
			return issue
		else:
			return None

	def tryBypassWithDowngradedHttpAndNoHeaders(self, baseRequestResponse, httpService):
		issue = []
		requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
		headers = requestInfo.getHeaders()
		newHeader = headers[0].replace("HTTP/1.1", "HTTP/1.0")

		requestBody = baseRequestResponse.getRequest()[requestInfo.getBodyOffset():]
		headersAsJavaSublist = ArrayList()
		headersAsJavaSublist.add(String(newHeader))

		newRequest = self.helpers.buildHttpMessage(headersAsJavaSublist, requestBody)
		newRequestResult = self.callbacks.makeHttpRequest(httpService, newRequest)
		newRequestStatusCode = str(self.helpers.analyzeResponse(newRequestResult.getResponse()).getStatusCode())

		if newRequestStatusCode == "200":
			responseHeaders = str(self.helpers.analyzeResponse(newRequestResult.getResponse()).getHeaders()).split(",")
			requestUrl = str(baseRequestResponse.getUrl())
			resultContentLength = "No CL in response"

			for header in responseHeaders:
				if "Content-Length: " in header:
					resultContentLength = header[17:]
					if resultContentLength[-1] == ']': # happens if CL header is the last header in response
						resultContentLength = resultContentLength.rstrip(']')

			requestNum = 2
			issue = []
			issue.append("<tr><td>" + str(requestNum) + "</td><td>" + requestUrl + "</td> <td>" + newRequestStatusCode + "</td> <td>" + resultContentLength + "</td></tr>")
			issue.append(newRequestResult)

		if len(issue) > 0:
			return issue
		else:
			return None




	def doPassiveScan(self, baseRequestResponse):
		return None

	def doActiveScan(self, baseRequestResponse, insertionPoint, isCalledFromMenu=False):
		response = self.helpers.analyzeResponse(baseRequestResponse.getResponse())
		if self.isInteresting(response) == False and isCalledFromMenu == False:
			return None

		else:
			issues = self.testRequest(baseRequestResponse)
			if issues != None:
				if isCalledFromMenu == True:
					for i in range(len(issues)):
						self.callbacks.addScanIssue(issues[i])
				else:
					return issues
			else:
				return None

	def testRequest(self, baseRequestResponse):
		queryPayloadsResults = []
		findings = []
		httpService = baseRequestResponse.getHttpService()

		#test for query-based issues
		queryPayloadsFromTable = []
		for rowIndex in range(self.frm.queryPayloadsTable.getRowCount()):
			queryPayloadsFromTable.append(str(self.frm.queryPayloadsTable.getValueAt(rowIndex, 0)))

		for payload in queryPayloadsFromTable:
			payload = payload.rstrip('\n')
			result = self.tryBypassWithQueryPayload(baseRequestResponse, httpService, self.generatePayloadsFromFile, payload)
			if result != None:
				queryPayloadsResults += result


		additionalResults = self.tryBypassWithQueryPayload(baseRequestResponse, httpService, self.generateAdditionalPayloads)

		#process query-based results
		if len(queryPayloadsResults) > 0:
			issueDetails = []
			issueHttpMessages = []
			issueHttpMessages.append(baseRequestResponse)

			for issue in queryPayloadsResults:
				issueDetails.append(issue[0])
				issueHttpMessages.append(issue[1])


			findings.append(
				CustomScanIssue(
				httpService,
				self.helpers.analyzeRequest(baseRequestResponse).getUrl(),
				issueHttpMessages,
				"Possible 403 Bypass",
				"<table><tr><td>Request #</td><td>URL</td><td>Status Code</td><td>Content Length</td></tr>" + "".join(issueDetails) + "</table>",
				"High",
				)
				)

		#replace GET with POST and empty Content-Length
		requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
		requestHeaders = requestInfo.getHeaders()
		if requestHeaders[0].startswith("GET"):
			postAndEmptyCLResult = self.tryBypassWithPOSTAndEmptyCL(baseRequestResponse, httpService)

			if postAndEmptyCLResult != None:
				issueDetails = []
				issueHttpMessages = []

				issueHttpMessages.append(baseRequestResponse)
				issueDetails.append(postAndEmptyCLResult[0])
				issueHttpMessages.append(postAndEmptyCLResult[1])


				findings.append(
					CustomScanIssue(
					httpService,
					self.helpers.analyzeRequest(baseRequestResponse).getUrl(),
					issueHttpMessages,
					"Possible 403 Bypass - Different Request Method",
					"<table><tr><td>Request #</td><td>URL</td><td>Status Code</td><td>Content Length</td></tr>" + "".join(issueDetails) + "</table>",
					"High",
					)
					)

		#change the protocol to HTTP/1.0 and remove all other headers
		downgradedHttpResult = self.tryBypassWithDowngradedHttpAndNoHeaders(baseRequestResponse, httpService)
		if downgradedHttpResult != None:
			issueDetails = []
			issueHttpMessages = []

			issueHttpMessages.append(baseRequestResponse)
			issueDetails.append(downgradedHttpResult[0])
			issueHttpMessages.append(downgradedHttpResult[1])

			findings.append(
				CustomScanIssue(
				httpService,
				self.helpers.analyzeRequest(baseRequestResponse).getUrl(),
				issueHttpMessages,
				"Possible 403 Bypass - Downgraded HTTP Version",
				"<table><tr><td>Request #</td><td>URL</td><td>Status Code</td><td>Content Length</td></tr>" + "".join(issueDetails) + "</table>",
				"High",
				)
				)

		if findings:
			print("Done and found something!")
			return findings
		else:
			print("Done and did not finding anything!")
			return None


	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
			return -1
		else:
			return 0

class CustomScanIssue (IScanIssue):
	def __init__(self, httpService, url, httpMessages, name, detail, severity):
		self._httpService = httpService
		self._url = url
		self._httpMessages = httpMessages
		self._name = name
		self._detail = detail
		self._severity = severity

	def getUrl(self):
		return self._url

	def getIssueName(self):
		return self._name

	def getIssueType(self):
		return 0

	def getSeverity(self):
		return self._severity

	def getConfidence(self):
		return "Firm"

	def getIssueBackground(self):
		return extentionName + " sent a request and got 403 response. " + extentionName + " sent another request and got 200 response, this may indicate a misconfiguration on the server side that allows access to forbidden pages."

	def getRemediationBackground(self):
		pass

	def getIssueDetail(self):
		return self._detail
	def getRemediationDetail(self):
		pass

	def getHttpMessages(self):
		return self._httpMessages

	def getHttpService(self):
		return self._httpService