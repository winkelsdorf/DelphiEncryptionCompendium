{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License. A copy of this licence is found in the root directory
  of this project in the file LICENCE.txt or alternatively at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*****************************************************************************}
unit DECCipherInterface;

interface

uses
  {$IFDEF FPC}
  SysUtils, Classes,
  {$ELSE}
  System.SysUtils, System.Classes,
  {$ENDIF}
  DECUtil, DECFormatBase;

type
  /// <summary>
  ///   Common interface for all ciphers. Some ciphers may have additional
  ///   methods/properties though!
  /// </summary>
  IDECCipher = Interface
    /// <summary>
    ///   Encrypts the contents of a given byte array
    /// </summary>
    /// <param name="Source">
    ///   Byte array with data to be encrypted
    /// </param>
    /// <returns>
    ///   Byte array with encrypted data
    /// </returns>
    function EncodeBytes(const Source: TBytes): TBytes;

    /// <summary>
    ///   Decrypts the contents of a given byte array
    /// </summary>
    /// <param name="Source">
    ///   Byte array with data to be decrypted
    /// </param>
    /// <returns>
    ///   Byte array with decrypted data
    /// </returns>
    function DecodeBytes(const Source: TBytes): TBytes;

    /// <summary>
    ///   Encrypts the data contained in a given stream
    /// </summary>
    /// <param name="Source">
    ///   Source stream containing the data to encrypt
    /// </param>
    /// <param name="Dest">
    ///   Destination stream, where the encrypted data shall be put in
    /// </param>
    /// <param name="DataSize">
    ///   Number of bytes of Source to be encrypted
    /// </param>
    /// <param name="Progress">
    ///   optional callback for reporting progress of the operation
    /// </param>
    procedure EncodeStream(const Source, Dest: TStream; DataSize: Int64;
                           const Progress: IDECProgress = nil);

    /// <summary>
    ///   Decrypts the data contained in a given stream
    /// </summary>
    /// <param name="Source">
    ///   Source stream containing the data to decrypt
    /// </param>
    /// <param name="Dest">
    ///   Destination stream, where the decrypted data shall be put in
    /// </param>
    /// <param name="DataSize">
    ///   Number of bytes of Source to be decrypted
    /// </param>
    /// <param name="Progress">
    ///   optional callback for reporting progress of the operation
    /// </param>
    procedure DecodeStream(const Source, Dest: TStream; DataSize: Int64;
                           const Progress: IDECProgress = nil);

    /// <summary>
    ///   Reads the contents of one file, encrypts it and stores it in another file
    /// </summary>
    /// <param name="SourceFileName">
    ///   Path and name of the file to encrypt
    /// </param>
    /// <param name="DestFileName">
    ///   Path and name of the file the encrypted data shall be stored in
    /// </param>
    /// <param name="Progress">
    ///   Optional event which can be passed to get information about the
    ///   progress of the encryption operation
    /// </param>
    procedure EncodeFile(const SourceFileName, DestFileName: string; const Progress: IDECProgress = nil);

    /// <summary>
    ///   Reads the contents of one file, decrypts it and stores it in another file
    /// </summary>
    /// <param name="SourceFileName">
    ///   Path and name of the file to decrypt
    /// </param>
    /// <param name="DestFileName">
    ///   Path and name of the file the decrypted data shall be stored in
    /// </param>
    /// <param name="Progress">
    ///   Optional event which can be passed to get information about the
    ///   progress of the decryption operation
    /// </param>
    procedure DecodeFile(const SourceFileName, DestFileName: string; const Progress: IDECProgress = nil);

    /// <summary>
    ///   Encrypts the contents of the passed unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as a byte array
    /// </returns>
    function EncodeStringToBytes(const Source: string; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Encrypts the contents of the passed RawByteString
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as a byte array
    /// </returns>
    function EncodeStringToBytes(const Source: RawByteString; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Encrypts the contents of the passed unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which will result in an 7-bit ASCII compatible string as we cannot
    ///   ensure that Unicode string processing will not alter/interpret some
    ///   byte combinations in a destructive way, making the encrypted string
    ///   un-decryptable.
    /// </remarks>
    function EncodeStringToString(const Source: string; Format: TDECFormatClass = nil): string; overload;

    /// <summary>
    ///   Encrypts the contents of the passed unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which will result in an 7-bit ASCII compatible string as we cannot
    ///   ensure that string processing will not alter/interpret some
    ///   byte combinations in a destructive way, making the encrypted string
    ///   un-decryptable.
    /// </remarks>
    function EncodeStringToString(const Source: RawByteString; Format: TDECFormatClass = nil): RawByteString; overload;

    /// <summary>
    ///   Decrypts the contents of the passed encrypted unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the still encrypted data, not the
    ///   encrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string as a byte array
    /// </returns>
    function DecodeStringToBytes(const Source: string; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Decrypts the contents of the passed encrypted RawByteString
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the still encrypted data, not the
    ///   encrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string as a byte array
    /// </returns>
    function DecodeStringToBytes(const Source: RawByteString; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Decrypts the contents of the passed Unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the encrypted data, not the
    ///   decrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which uses an 7-bit ASCII compatible string as input so that it
    ///   didn't get altered by Unicode string processing in some hafrmful way
    /// </remarks>
    function DecodeStringToString(const Source: string; Format: TDECFormatClass = nil): string; overload;

    /// <summary>
    ///   Decrypts the contents of the passed RawByteString string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the encrypted data, not the
    ///   decrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which uses an 7-bit ASCII compatible string as input so that it
    ///   didn't get altered by string processing in some hafrmful way
    /// </remarks>
    function DecodeStringToString(const Source: RawByteString; Format: TDECFormatClass = nil): RawByteString; overload;

{$IFDEF ANSISTRINGSUPPORTED}
    /// <summary>
    ///   Encrypts the contents of the passed Ansistring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as a byte array
    /// </returns>
    function EncodeStringToBytes(const Source: AnsiString; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Encrypts the contents of the passed Ansistring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as an AnsiString
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which will result in an 7-bit ASCII compatible string as we cannot
    ///   ensure that string processing will not alter/interpret some
    ///   byte combinations in a destructive way, making the encrypted string
    ///   un-decryptable.
    /// </remarks>
    function EncodeStringToString(const Source: AnsiString; Format: TDECFormatClass = nil): AnsiString; overload;

    /// <summary>
    ///   Decrypts the contents of the passed encrypted Ansistring
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the still encrypted data, not the
    ///   encrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string as a byte array
    /// </returns>
    function DecodeStringToBytes(const Source: AnsiString; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Decrypts the contents of the passed AnsiString string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the encrypted data, not the
    ///   decrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which uses an 7-bit ASCII compatible string as input so that it
    ///   didn't get altered by string processing in some hafrmful way
    /// </remarks>
    function DecodeStringToString(const Source: AnsiString; Format: TDECFormatClass = nil): AnsiString; overload;
{$ENDIF}

{$IFNDEF NEXTGEN}
    /// <summary>
    ///   Encrypts the contents of the passed Widestring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as a byte array
    /// </returns>
    function EncodeStringToBytes(const Source: WideString; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Encrypts the contents of the passed Widestring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as an WideString
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which will result in an 7-bit ASCII compatible string as we cannot
    ///   ensure that string processing will not alter/interpret some
    ///   byte combinations in a destructive way, making the encrypted string
    ///   un-decryptable.
    /// </remarks>
    function EncodeStringToString(const Source: WideString; Format: TDECFormatClass = nil): WideString; overload;

    /// <summary>
    ///   Decrypts the contents of the passed encrypted Widestring
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the still encrypted data, not the
    ///   encrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string as a byte array
    /// </returns>
    function DecodeStringToBytes(const Source: WideString; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Decrypts the contents of the passed WideString string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the encrypted data, not the
    ///   decrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which uses an 7-bit ASCII compatible string as input so that it
    ///   didn't get altered by string processing in some hafrmful way
    /// </remarks>
    function DecodeStringToString(const Source: WideString; Format: TDECFormatClass = nil): WideString; overload;
{$ENDIF}
  end;

implementation

end.
