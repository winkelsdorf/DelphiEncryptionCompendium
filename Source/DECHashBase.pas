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

/// <summary>
///   Base unit for all the hash algorithms. Contains implementation of the key
///   deviation algorithms as well.
/// </summary>
unit DECHashBase;

interface

{$INCLUDE DECOptions.inc}

uses
  {$IFDEF FPC}
  SysUtils, Classes,
  {$ELSE}
  System.SysUtils, System.Classes,
  {$ENDIF}
  Generics.Collections,
  DECBaseClass, DECFormatBase, DECUtil, DECTypes, DECHashInterface;

type
  /// <summary>
  ///   Meta class for all the hashing classes in order to support the
  ///   registration mechanism
  /// </summary>
  TDECHashClass = class of TDECHash;

  /// <summary>
  ///   Type of the KDF variant
  /// </summary>
  TKDFType = (ktKDF1, ktKDF2, ktKDF3);

  /// <summary>
  ///   Base class for all hash algorithm implementation classes
  /// </summary>
  {$IFDEF FPC}
  TDECHash = class(TDECObject)  // findet Methoden des Interface nicht ... sucht nach AnsiString statt RawByteString und findet das natürlich nicht
  {$ELSE}
  TDECHash = class(TDECObject, IDECHash)
  {$ENDIF}
  strict private
    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    ///   IEEE P1363 Working Group, ISO 18033-2:2004
    ///   This is either KDF1 or KDF2 depending on KDFType
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="DataSize">
    ///   Size in bytes of the source data passed.
    /// </param>
    /// <param name="Seed">
    ///   Start value for pseudo random number generator
    /// </param>
    /// <param name="SeedSize">
    ///   Size of the seed in byte.
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <param name="KDFType">
    ///   Type of the algorithm: 1 = KDF1, 2 = KDF2 and 3 = KDF 3
    /// </param>
    /// <returns>
    ///   Returns the new derrived key.
    /// </returns>
    class function KDFInternal(const Data; DataSize: Integer; const Seed;
                               SeedSize, MaskSize: Integer; KDFType: TKDFType): TBytes; inline;

    /// <summary>
    ///   Raises an EDECHashException hash algorithm not initialized exception
    /// </summary>
    procedure RaiseHashNotInitialized;

    /// <summary>
    ///   Returns the current value of the padding byte used to fill up data
    ///   if necessary
    /// </summary>
    function GetPaddingByte: Byte;
    /// <summary>
    ///   Changes the value of the padding byte used to fill up data
    ///   if necessary
    /// </summary>
    /// <param name="Value">
    ///   New value for the padding byte
    /// </param>
    procedure SetPaddingByte(Value: Byte);
  strict protected
    FCount: array[0..7] of UInt32;
    FBuffer: PByteArray;
    FBufferSize: Integer;
    FBufferIndex: Integer;
    FPaddingByte: Byte;
    /// <summary>
    ///   This abstract method has to be overridden by each concrete hash algorithm
    ///   to initialize the necessary data structures.
    /// </summary>
    procedure DoInit; virtual; abstract;

    procedure DoTransform(Buffer: PUInt32Array); virtual; abstract;
    /// <summary>
    ///   This abstract method has to be overridden by each concrete hash algorithm
    ///   to finalize the calculation of a hash value over the data passed.
    /// </summary>
    procedure DoDone; virtual; abstract;
    procedure Increment8(var Value; Add: UInt32);
    /// <summary>
    ///   Raises an EDECHashException overflow error
    /// </summary>
    procedure RaiseHashOverflowError;

{ TODO : Sollte ersetzt werden zusammen mit PByteArray, wird aber auch in DECRandom benutzt! }
    function Digest: PByteArray; virtual; abstract;
  public
    /// <summary>
    ///   Fees internal resources
    /// </summary>
    destructor Destroy; override;
    /// <summary>
    ///   Generic initialization of internal data structures. Additionally the
    ///   internal algorithm specific (because of being overridden by each
    ///   hash algorithm) DoInit method. Needs to be called before each hash
    ///   calculation.
    /// </summary>
    procedure Init;
    /// <summary>
    ///   Processes one chunk of data to be hashed.
    /// </summary>
    /// <param name="Data">
    ///   Data on which the hash value shall be calculated on
    /// </param>
    /// <param name="DataSize">
    ///   Size of the data in bytes
    /// </param>
    procedure Calc(const Data; DataSize: Integer); virtual;

    /// <summary>
    ///   Frees dynamically allocated buffers in a way which safeguards agains
    ///   data stealing by other methods which afterwards might allocate this memory.
    ///   Additionaly calls the algorithm spercific DoDone method.
    /// </summary>
    procedure Done;

    /// <summary>
    ///   Returns the calculated hash value as byte array
    /// </summary>
    function DigestAsBytes: TBytes; virtual;

    /// <summary>
    ///   Returns the calculated hash value as formatted Unicode string
    /// </summary>
    /// <param name="Format">
    ///   Optional parameter. If a formatting class is being passed the formatting
    ///   will be applied to the returned string. Otherwise no formatting is
    ///   being used.
    /// </param>
    /// <returns>
    ///   Hash value of the last performed hash calculation
    /// </returns>
    /// <remarks>
    ///   We recommend to use a formatting which results in 7 bit ASCII chars
    ///   being returned, otherwise the conversion into the Unicode string might
    ///   result in strange characters in the returned result.
    /// </remarks>
    function DigestAsString(Format: TDECFormatClass = nil): string;
    /// <summary>
    ///   Returns the calculated hash value as formatted RawByteString
    /// </summary>
    /// <param name="Format">
    ///   Optional parameter. If a formatting class is being passed the formatting
    ///   will be applied to the returned string. Otherwise no formatting is
    ///   being used.
    /// </param>
    /// <returns>
    ///   Hash value of the last performed hash calculation
    /// </returns>
    /// <remarks>
    ///   We recommend to use a formatting which results in 7 bit ASCII chars
    ///   being returned, otherwise the conversion into the RawByteString might
    ///   result in strange characters in the returned result.
    /// </remarks>
    function DigestAsRawByteString(Format: TDECFormatClass = nil): RawByteString;

    /// <summary>
    ///   Gives the length of the calculated hash value in byte. Needs to be
    ///   overridden in concrete hash implementations.
    /// </summary>
    class function DigestSize: UInt32; virtual;
    /// <summary>
    ///   Gives the length of the blocks the hash value is being calculated
    ///   on in byte. Needs to be overridden in concrete hash implementations.
    /// </summary>
    class function BlockSize: UInt32; virtual;

    /// <summary>
    ///   List of registered DEC classes. Key is the Identity of the class.
    /// </summary>
    class var ClassList : TDECClassList;

    /// <summary>
    ///   Tries to find a class type by its name
    /// </summary>
    /// <param name="Name">
    ///   Name to look for in the list
    /// </param>
    /// <returns>
    ///   Returns the class type if found. if it could not be found a
    ///   EDECClassNotRegisteredException will be thrown
    /// </returns>
    class function ClassByName(const Name: string): TDECHashClass;

    /// <summary>
    ///   Tries to find a class type by its numeric identity DEC assigned to it.
    ///   Useful for file headers, so they can easily encode numerically which
    ///   cipher class was being used.
    /// </summary>
    /// <param name="Identity">
    ///   Identity to look for
    /// </param>
    /// <returns>
    ///   Returns the class type of the class with the specified identity value
    ///   or throws an EDECClassNotRegisteredException exception if no class
    ///   with the given identity has been found
    /// </returns>
    class function ClassByIdentity(Identity: Int64): TDECHashClass;

    /// <summary>
    ///   Detects whether the given hash class is one particularily suited
    ///   for storing hashes of passwords
    /// </summary>
    /// <returns>
    ///   true if it's a hash class specifically designed to store password
    ///   hashes, false for ordinary hash algorithms.
    /// </returns>
    class function IsPasswordHash: Boolean;

    // hash calculation wrappers

    /// <summary>
    ///   Calculates the hash value (digest) for a given buffer
    /// </summary>
    /// <param name="Buffer">
    ///   Untyped buffer the hash shall be calculated for
    /// </param>
    /// <param name="BufferSize">
    ///   Size of the buffer in byte
    /// </param>
    /// <returns>
    ///   Byte array with the calculated hash value
    /// </returns>
    function CalcBuffer(const Buffer; BufferSize: Integer): TBytes;
    /// <summary>
    ///   Calculates the hash value (digest) for a given buffer
    /// </summary>
    /// <param name="Data">
    ///   The TBytes array the hash shall be calculated on
    /// </param>
    /// <returns>
    ///   Byte array with the calculated hash value
    /// </returns>
    function CalcBytes(const Data: TBytes): TBytes;

    /// <summary>
    ///   Calculates the hash value (digest) for a given unicode string
    /// </summary>
    /// <param name="Value">
    ///   The string the hash shall be calculated on
    /// </param>
    /// <param name="Format">
    ///   Formatting class from DECFormat. The formatting will be applied to the
    ///   returned digest value. This parameter is optional.
    /// </param>
    /// <returns>
    ///   string with the calculated hash value
    /// </returns>
    function CalcString(const Value: string; Format: TDECFormatClass = nil): string; overload;
    /// <summary>
    ///   Calculates the hash value (digest) for a given rawbytestring
    /// </summary>
    /// <param name="Value">
    ///   The string the hash shall be calculated on
    /// </param>
    /// <param name="Format">
    ///   Formatting class from DECFormat. The formatting will be applied to the
    ///   returned digest value. This parameter is optional.
    /// </param>
    /// <returns>
    ///   string with the calculated hash value
    /// </returns>
    function CalcString(const Value: RawByteString; Format: TDECFormatClass): RawByteString; overload;

    /// <summary>
    ///   Calculates the hash value over a given stream of bytes
    /// </summary>
    /// <param name="Stream">
    ///   Memory or file stream over which the hash value shall be calculated.
    ///   The stream must be assigned and the hash value will either be calculated
    ///   from the beginning of the stream (if size < 0) or from the current
    ///   stream position (size > 0) to the end
    /// </param>
    /// <param name="Size">
    ///   Number of bytes within the stream over which to calculate the hash value
    /// </param>
    /// <param name="HashResult">
    ///   In this byte array the calculated hash value will be returned
    /// </param>
    /// <param name="Progress">
    ///   Optional callback routine. It can be used to display the progress of
    ///   the operation.
    /// </param>
    procedure CalcStream(const Stream: TStream; Size: Int64; var HashResult: TBytes;
                         const Progress: IDECProgress = nil); overload;
    /// <summary>
    ///   Calculates the hash value over a givens stream of bytes
    /// </summary>
    /// <param name="Stream">
    ///   Memory or file stream over which the hash value shall be calculated.
    ///   The stream must be assigned and the hash value will either be calculated
    ///   from the beginning of the stream (if size < 0) or from the current
    ///   stream position (size > 0) to the end
    /// </param>
    /// <param name="Size">
    ///   Number of bytes within the stream over which to calculate the hash value
    /// </param>
    /// <param name="Format">
    ///   Optional formatting class. The formatting of that will be applied to
    ///   the returned hash value.
    /// </param>
    /// <param name="Progress">
    ///   Optional callback routine. It can be used to display the progress of
    ///   the operation.
    /// </param>
    /// <returns>
    ///   Hash value over the bytes in the stream, formatted with the formatting
    ///   passed as format parameter, if used.
    /// </returns>
    function CalcStream(const Stream: TStream; Size: Int64; Format: TDECFormatClass = nil;
                        const Progress: IDECProgress = nil): RawByteString; overload;

    /// <summary>
    ///   Calculates the hash value over the contents of a given file
    /// </summary>
    /// <param name="FileName">
    ///   Path and name of the file to be processed
    /// </param>
    /// <param name="HashResult">
    ///   Here the resulting hash value is being returned as byte array
    /// </param>
    /// <param name="Progress">
    ///   Optional callback. If being used the hash calculation will call it from
    ///   time to time to return the current progress of the operation
    /// </param>
    procedure CalcFile(const FileName: string; var HashResult: TBytes;
                       const Progress: IDECProgress = nil); overload;
    /// <summary>
    ///   Calculates the hash value over the contents of a given file
    /// </summary>
    /// <param name="FileName">
    ///   Path and name of the file to be processed
    /// </param>
    /// <param name="Format">
    ///   Optional parameter: Formatting class. If being used the formatting is
    ///   being applied to the returned string with the calculated hash value
    /// </param>
    /// <param name="Progress">
    ///   Optional callback. If being used the hash calculation will call it from
    ///   time to time to return the current progress of the operation
    /// </param>
    /// <returns>
    ///   Calculated hash value as RawByteString.
    /// </returns>
    /// <remarks>
    ///   We recommend to use a formatting which results in 7 bit ASCII chars
    ///   being returned, otherwise the conversion into the RawByteString might
    ///   result in strange characters in the returned result.
    /// </remarks>
    function CalcFile(const FileName: string; Format: TDECFormatClass = nil;
                      const Progress: IDECProgress = nil): RawByteString; overload;

    // mask generation

    /// <summary>
    ///   Mask generation: generates an output based on the data given which is
    ///   similar to a hash function but in contrast does not have a fixed output
    ///   length. Use of a MGF is desirable in cases where a fixed-size hash
    ///   would be inadequate. Examples include generating padding, producing
    ///   one time pads or keystreams in symmetric key encryption, and yielding
    ///   outputs for pseudorandom number generators
    /// </summary>
    /// <param name="Data">
    ///   Data from which to generate a mask from
    /// </param>
    /// <param name="DataSize">
    ///   Size of the input data in bytes
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the returned mask in bytes
    /// </param>
    /// <returns>
    ///   Mask such that one cannot determine the data which had been given to
    ///   generate this mask from.
    /// </returns>
    class function MGF1(const Data; DataSize, MaskSize: Integer): TBytes; overload;
    /// <summary>
    ///   Mask generation: generates an output based on the data given which is
    ///   similar to a hash function but incontrast does not have a fixed output
    ///   length. Use of a MGF is desirable in cases where a fixed-size hash
    ///   would be inadequate. Examples include generating padding, producing
    ///   one time pads or keystreams in symmetric key encryption, and yielding
    ///   outputs for pseudorandom number generators
    /// </summary>
    /// <param name="Data">
    ///   Data from which to generate a mask from
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the returned mask in bytes
    /// </param>
    /// <returns>
    ///   Mask such that one cannot determine the data which had been given to
    ///   generate this mask from.
    /// </returns>
    class function MGF1(const Data: TBytes; MaskSize: Integer): TBytes; overload;

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    ///   IEEE P1363 Working Group, ISO 18033-2:2004
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="DataSize">
    ///   Size in bytes of the source data passed.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="SeedSize">
    ///   Size of the seed/salt in byte.
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    /// <remarks>
    ///   In earlier versions there was an optional format parameter. This has
    ///   been removed as this is a base class. The method might not have
    ///   returned a result with the MaskSize specified, as the formatting might
    ///   have had to alter this. This would have been illogical.
    /// </remarks>
    class function KDF1(const Data; DataSize: Integer; const Seed;
                        SeedSize, MaskSize: Integer): TBytes; overload;

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    ///   IEEE P1363 Working Group, ISO 18033-2:2004
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    class function KDF1(const Data, Seed: TBytes; MaskSize: Integer): TBytes; overload;

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    ///   IEEE P1363 Working Group, ISO 18033-2:2004
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="DataSize">
    ///   Size in bytes of the source data passed.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="SeedSize">
    ///   Size of the seed/salt in byte.
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    /// <remarks>
    ///   In earlier versions there was an optional format parameter. This has
    ///   been removed as this is a base class. The method might not have
    ///   returned a result with the MaskSize specified, as the formatting might
    ///   have had to alter this. This would have been illogical.
    /// </remarks>
    class function KDF2(const Data; DataSize: Integer; const Seed;
                        SeedSize, MaskSize: Integer): TBytes; overload;

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    ///   IEEE P1363 Working Group, ISO 18033-2:2004
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="Seed">
    ///   Start value for pseudo random number generator
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    class function KDF2(const Data, Seed: TBytes; MaskSize: Integer): TBytes; overload;

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="DataSize">
    ///   Size in bytes of the source data passed.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="SeedSize">
    ///   Size of the seed/salt in byte.
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    /// <remarks>
    ///   In earlier versions there was an optional format parameter. This has
    ///   been removed as this is a base class. The method might not have
    ///   returned a result with the MaskSize specified, as the formatting might
    ///   have had to alter this. This would have been illogical.
    /// </remarks>
    class function KDF3(const Data; DataSize: Integer; const Seed;
                        SeedSize, MaskSize: Integer): TBytes; overload;

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    class function KDF3(const Data, Seed: TBytes; MaskSize: Integer): TBytes; overload;

    // DEC's own KDF + MGF

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys. The alrorithm
    ///   implemented by this method does not follow any official standard.
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="DataSize">
    ///   Size in bytes of the source data passed.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="SeedSize">
    ///   Size of the seed/salt in byte.
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <param name="Index">
    ///   Optional parameter: can be used to specify a different default value
    ///   for the index variable used in the algorithm.
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    class function KDFx(const Data; DataSize: Integer; const Seed; SeedSize, MaskSize: Integer; Index: UInt32 = 1): TBytes; overload;
    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    /// </summary>
    /// <remarks>
    ///   This variant of the algorithm does not follow an official standard.
    ///   It has been created by the original author of DEC.
    /// </remarks>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <param name="Index">
    ///   Optional parameter: can be used to specify a different default value
    ///   for the index variable used in the algorithm.
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    class function KDFx(const Data, Seed: TBytes; MaskSize: Integer; Index: UInt32 = 1): TBytes; overload;

    /// <summary>
    ///   Mask generation: generates an output based on the data given which is
    ///   similar to a hash function but incontrast does not have a fixed output
    ///   length. Use of a MGF is desirable in cases where a fixed-size hash
    ///   would be inadequate. Examples include generating padding, producing
    ///   one time pads or keystreams in symmetric key encryption, and yielding
    ///   outputs for pseudorandom number generators.
    /// </summary>
    /// <remarks>
    ///   This variant of the algorithm does not follow an official standard.
    ///   It has been created by the original author of DEC.
    /// </remarks>
    /// <param name="Data">
    ///   Data from which to generate a mask from
    /// </param>
    /// <param name="DataSize">
    ///   Size of the passed data in bytes
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the returned mask in bytes
    /// </param>
    /// <param name="Index">
    ///   Looks like this is a salt applied to each byte of output data?
{ TODO : Clarify this parameter }
    /// </param>
    /// <returns>
    ///   Mask such that one cannot determine the data which had been given to
    ///   generate this mask from.
    /// </returns>
    class function MGFx(const Data; DataSize, MaskSize: Integer; Index: UInt32 = 1): TBytes; overload;
    /// <summary>
    ///   Mask generation: generates an output based on the data given which is
    ///   similar to a hash function but incontrast does not have a fixed output
    ///   length. Use of a MGF is desirable in cases where a fixed-size hash
    ///   would be inadequate. Examples include generating padding, producing
    ///   one time pads or keystreams in symmetric key encryption, and yielding
    ///   outputs for pseudorandom number generators.
    /// </summary>
    /// <remarks>
    ///   This variant of the algorithm does not follow an official standard.
    ///   It has been created by the original author of DEC.
    /// </remarks>
    /// <param name="Data">
    ///   Data from which to generate a mask from
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the returned mask in bytes
    /// </param>
    /// <param name="Index">
    ///
    /// </param>
    /// <returns>
    ///   Mask such that one cannot determine the data which had been given to
    ///   generate this mask from.
    /// </returns>
    class function MGFx(const Data: TBytes; MaskSize: Integer; Index: UInt32 = 1): TBytes; overload;

    /// <summary>
    ///   Defines the byte used in the KDF methods to padd the end of the data
    ///   if the length of the data cannot be divided by required size for the
    ///   hash algorithm without reminder
    /// </summary>
    property PaddingByte: Byte read GetPaddingByte write SetPaddingByte;
  end;

  /// <summary>
  ///   All hash classes with hash algorithms specially developed for password
  ///   hashing should inherit from this class in order to be able to distinguish
  ///   those from normal hash algorithms not really meant to be used for password
  ///   hashing.
  /// </summary>
  TDECPasswordHash = class(TDECHash);

  /// <summary>
  ///   Type needed to be able to remove with statements in KDF functions
  /// </summary>
  TDECHashstype = class of TDECHash;

/// <summary>
///   Returns the passed hash class type if it is not nil. Otherwise the
///   class type class set per SetDefaultHashClass is being returned. If using
///   the DECHash unit THash_SHA256 is registered in the initialization, otherwise
///   nil might be returned!
/// </summary>
/// <param name="HashClass">
///   Class type of a hash class like THash_SHA256. If nil is passed the one set
///   as default is returned.
/// </param>
/// <returns>
///   Passed class type or defined default hash class type, depending on
///   HashClass parameter value.
/// </returns>
function ValidHash(HashClass: TDECHashClass = nil): TDECHashClass;

/// <summary>
///   Defines which cipher class to return by ValidCipher if passing nil to that
/// </summary>
/// <param name="HashClass">
///   Class type of a hash class to return by ValidHash if passing nil to
///   that one. This parameter should not be nil!
/// </param>
procedure SetDefaultHashClass(HashClass: TDECHashClass);

implementation

resourcestring
  sHashNotInitialized     = 'Hash must be initialized';
  sRaiseHashOverflowError = 'Hash Overflow: Too many bits processed';
  sHashNoDefault          = 'No default hash has been registered';

var
  /// <summary>
  ///   Hash class returned by ValidHash if nil is passed as parameter to it
  /// </summary>
  FDefaultHashClass: TDECHashClass;

function ValidHash(HashClass: TDECHashClass): TDECHashClass;
begin
  if Assigned(HashClass) then
    Result := HashClass
  else
    Result := FDefaultHashClass;

  if not Assigned(Result) then
    raise EDECHashException.CreateRes(@sHashNoDefault);
end;

procedure SetDefaultHashClass(HashClass: TDECHashClass);
begin
  Assert(Assigned(HashClass), 'Do not set a nil default hash class!');

  FDefaultHashClass := HashClass;
end;

{ TDECHash }

destructor TDECHash.Destroy;
begin
  ProtectBuffer(Digest^, DigestSize);
  ProtectBuffer(FBuffer^, FBufferSize);
  FreeMem(FBuffer, FBufferSize);

  inherited Destroy;
end;

procedure TDECHash.Init;
begin
  FBufferIndex := 0;
  FBufferSize := BlockSize;
  // ReallocMemory instead of ReallocMem due to C++ compatibility as per 10.1 help
  FBuffer := ReallocMemory(FBuffer, FBufferSize);

  FillChar(FBuffer^, FBufferSize, 0);
  FillChar(FCount, SizeOf(FCount), 0);
  DoInit;
end;

procedure TDECHash.Done;
begin
  DoDone;
  ProtectBuffer(FBuffer^, FBufferSize);

  FBufferSize := 0;
  // ReallocMemory instead of ReallocMem due to C++ compatibility as per 10.1 help
  // It is necessary to reallocate the buffer as FreeMem in destructor wouldn't
  // accept a nil pointer on some platforms.
  FBuffer := ReallocMemory(FBuffer, 0);
end;

function TDECHash.GetPaddingByte: Byte;
begin
  Result := FPaddingByte;
end;

class function TDECHash.IsPasswordHash: Boolean;
var
  Parent : TClass;
begin
  Result := false;

  Parent := ClassParent;
  while assigned(Parent) do
  begin
    if (ClassParent = TDECPasswordHash) then
    begin
      Result := true;
      break;
    end
    else
      Parent := Parent.ClassParent;
  end;
end;

procedure TDECHash.Increment8(var Value; Add: UInt32);
// Value := Value + 8 * Add
// Value is array[0..7] of UInt32
{ TODO -oNormanNG -cCodeReview : !!Unbedingt noch einmal prüfen, ob das wirklich so alles stimmt!!
Mein Versuch der Umsetzung von Increment8 in ASM.
Die Implementierung zuvor hat immer Zugriffsverletzungen ausgelöst.
Vermutung: die alte Implementierung lag ursprünglich ausserhalb der Klasse und wurde später
in die Klasse verschoben. Dabei verändert sich aber die Nutzung der Register, da zusätzlich
der SELF-Parameter in EAX übergeben wird. Beim Schreiben nach auf Value wurde dann in die Instanz (Self)
geschrieben -> peng
}
{$IF defined(X86ASM) or defined(X64ASM)}
  {$IFDEF X86ASM}
  //   type TData = packed array[0..7] of UInt32;  8x32bit
  //   TypeOf Param "Value" = TData
  //
  //   EAX = Self
  //   EDX = Pointer to "Value"
  //   ECX = Value of "ADD"
  register; // redundant but informative
  asm
      LEA EAX,[ECX*8]              //                      EAX := ADD * 8
      SHR ECX,29                   //                      29bit nach rechts schieben, 3bit beiben stehen
      ADD [EDX].DWord[00],EAX      // add [edx], eax       TData(Value)[00] := TData(Value)[00] + EAX
      ADC [EDX].DWord[04],ECX      // adc [edx+$04], ecx   TData(Value)[04] := TData(Value)[04] + ECX + Carry
      ADC [EDX].DWord[08],0        // adc [edx+$08], 0     TData(Value)[08] := TData(Value)[08] + 0 + Carry
      ADC [EDX].DWord[12],0        // adc [edx+$0c], 0     TData(Value)[12] := TData(Value)[12] + 0 + Carry
      ADC [EDX].DWord[16],0        // adc [edx+$10], 0     TData(Value)[16] := TData(Value)[16] + 0 + Carry
      ADC [EDX].DWord[20],0        // adc [edx+$14], 0     TData(Value)[20] := TData(Value)[20] + 0 + Carry
      ADC [EDX].DWord[24],0        // adc [edx+$18], 0     TData(Value)[24] := TData(Value)[24] + 0 + Carry
      ADC [EDX].DWord[28],0        // adc [edx+$1c], 0     TData(Value)[28] := TData(Value)[28] + 0 + Carry
      JC  RaiseHashOverflowError
  end;
  {$ENDIF !X86ASM}
  {$IFDEF X64ASM}
  //   type TData = packed array[0..3] of UInt64;  4x64bit
  //   TypeOf Param "Value" = TData
  //
  //   RCX = Self
  //   RDX = Pointer to "Value"
  //   R8D = Value of "ADD"
  register; // redundant but informative
  asm
    SHL R8, 3                      // R8 := Add * 8       the caller writes to R8D what automatically clears the high DWORD of R8
    ADD QWORD PTR [RDX     ], R8   // add [rdx], r8       TData(Value)[00] := TData(Value)[00] + R8
    ADD QWORD PTR [RDX +  8], 0    // add [rdx+$08], 0    TData(Value)[08] := TData(Value)[08] + 0 + Carry
    ADD QWORD PTR [RDX + 16], 0    // add [rdx+$10], 0    TData(Value)[16] := TData(Value)[16] + 0 + Carry
    ADD QWORD PTR [RDX + 24], 0    // add [rdx+$18], 0    TData(Value)[24] := TData(Value)[24] + 0 + Carry
    JC RaiseHashOverflowError;
  end;
  {$ENDIF !X64ASM}
{$ELSE PUREPASCAL}
type
  TData = packed array[0..7] of UInt32;

var
  HiBits: UInt32;
  Add8: UInt32;
  Carry: Boolean;

  procedure AddC(var Value: UInt32; const Add: UInt32; var Carry: Boolean);
  begin
    if Carry then
    begin
      Value := Value + 1;
      Carry := (Value = 0); // we might cause another overflow by adding the carry bit
    end
    else
      Carry := False;

    Value := Value + Add;
    Carry := Carry or (Value < Add); // set Carry Flag on overflow
  end;

begin
  HiBits := Add shr 29; // Save most significant 3 bits in case an overflow occurs
  Add8 := Add * 8;
  Carry := False;

  AddC(TData(Value)[0], Add8, Carry);
  AddC(TData(Value)[1], HiBits, Carry);
  AddC(TData(Value)[2], 0, Carry);
  AddC(TData(Value)[3], 0, Carry);
  AddC(TData(Value)[4], 0, Carry);
  AddC(TData(Value)[5], 0, Carry);
  AddC(TData(Value)[6], 0, Carry);
  AddC(TData(Value)[7], 0, Carry);

  if Carry then
    RaiseHashOverflowError;
end;
{$ENDIF PUREPASCAL}

procedure TDECHash.RaiseHashOverflowError;
begin
  raise EDECHashException.CreateRes(@sRaiseHashOverflowError);
end;

procedure TDECHash.SetPaddingByte(Value: Byte);
begin
  FPaddingByte := Value;
end;

procedure TDECHash.RaiseHashNotInitialized;
begin
  raise EDECHashException.CreateRes(@sHashNotInitialized);
end;

procedure TDECHash.Calc(const Data; DataSize: Integer);
var
  Remain: Integer;
  Value: PByte;
begin
  if DataSize <= 0 then
    Exit;

  if not Assigned(FBuffer) then
    RaiseHashNotInitialized;

  Increment8(FCount, DataSize);
  Value := @TByteArray(Data)[0];

  if FBufferIndex > 0 then
  begin
    Remain := FBufferSize - FBufferIndex;
    if DataSize < Remain then
    begin
      Move(Value^, FBuffer[FBufferIndex], DataSize);
      Inc(FBufferIndex, DataSize);
      Exit;
    end;
    Move(Value^, FBuffer[FBufferIndex], Remain);
    DoTransform(Pointer(FBuffer));
    Dec(DataSize, Remain);
    Inc(Value, Remain);
  end;

  while DataSize >= FBufferSize do
  begin
    DoTransform(Pointer(Value));
    Inc(Value, FBufferSize);
    Dec(DataSize, FBufferSize);
  end;

  Move(Value^, FBuffer^, DataSize);
  FBufferIndex := DataSize;
end;

function TDECHash.DigestAsBytes: TBytes;
begin
  SetLength(Result, DigestSize);
  if DigestSize <> 0 then
    Move(Digest^, Result[0], DigestSize);
end;

function TDECHash.DigestAsRawByteString(Format: TDECFormatClass): RawByteString;
begin
  Result := BytesToRawString(ValidFormat(Format).Encode(DigestAsBytes));
end;

function TDECHash.DigestAsString(Format: TDECFormatClass): string;
begin
  Result := StringOf(ValidFormat(Format).Encode(DigestAsBytes));
end;

class function TDECHash.DigestSize: UInt32;
begin
  // C++ does not support virtual static functions thus the base cannot be
  // marked 'abstract'. This is our workaround:
  raise EDECAbstractError.Create(Self);
end;

class function TDECHash.BlockSize: UInt32;
begin
  // C++ does not support virtual static functions thus the base cannot be
  // marked 'abstract'. This is our workaround:
  raise EDECAbstractError.Create(Self);
end;

function TDECHash.CalcBuffer(const Buffer; BufferSize: Integer): TBytes;
begin
  Init;
  Calc(Buffer, BufferSize);
  Done;
  Result := DigestAsBytes;
end;

function TDECHash.CalcBytes(const Data: TBytes): TBytes;
begin
  SetLength(Result, 0);
  if Length(Data) > 0 then
    Result := CalcBuffer(Data[0], Length(Data))
  else
    Result := CalcBuffer(Data, Length(Data))
end;

function TDECHash.CalcString(const Value: string; Format: TDECFormatClass): string;
var
  Size : Integer;
  Data : TBytes;
begin
  Result := '';
  if Length(Value) > 0 then
  begin
    Size := Length(Value) * SizeOf(Value[low(Value)]);
    Data := CalcBuffer(Value[low(Value)], Size);
    Result := StringOf(ValidFormat(Format).Encode(Data));
  end
  else
  begin
    SetLength(Data, 0);
    Result := StringOf(ValidFormat(Format).Encode(CalcBuffer(Data, 0)));
  end;
end;

function TDECHash.CalcString(const Value: RawByteString; Format: TDECFormatClass): RawByteString;
var
  Buf : TBytes;
begin
  Result := '';
  if Length(Value) > 0 then
    Result := BytesToRawString(
                ValidFormat(Format).Encode(
                  CalcBuffer(Value[low(Value)],
                             Length(Value) * SizeOf(Value[low(Value)]))))
  else
  begin
    SetLength(Buf, 0);
    Result := BytesToRawString(ValidFormat(Format).Encode(CalcBuffer(Buf, 0)));
  end;
end;

class function TDECHash.ClassByIdentity(Identity: Int64): TDECHashClass;
begin
  Result := TDECHashClass(ClassList.ClassByIdentity(Identity));
end;

class function TDECHash.ClassByName(const Name: string): TDECHashClass;
begin
  Result := TDECHashClass(ClassList.ClassByName(Name));
end;

procedure TDECHash.CalcStream(const Stream: TStream; Size: Int64;
  var HashResult: TBytes; const Progress: IDECProgress);
var
  Buffer: TBytes;
  Bytes: Integer;
  Min, Max, Pos: Int64;
begin
  Assert(Assigned(Stream), 'Stream to calculate hash on is not assigned');

  SetLength(HashResult, 0);
  Min := 0;
  Max := 0;
  try
    Init;

    if StreamBufferSize <= 0 then
      StreamBufferSize := 8192;

    if Size < 0 then
    begin
      Stream.Position := 0;
      Size := Stream.Size;
      Pos := 0;
    end
    else
      Pos := Stream.Position;

    Bytes := StreamBufferSize mod FBufferSize;

    if Bytes = 0 then
      Bytes := StreamBufferSize
    else
      Bytes := StreamBufferSize + FBufferSize - Bytes;

    if Bytes > Size then
      SetLength(Buffer, Size)
    else
      SetLength(Buffer, Bytes);

    Min := Pos;
    Max := Pos + Size;

    while Size > 0 do
    begin
      if Assigned(Progress) then
        Progress.OnProgress(Min, Max, Pos);
      Bytes := Length(Buffer);
      if Bytes > Size then
        Bytes := Size;
      Stream.ReadBuffer(Buffer[0], Bytes);
      Calc(Buffer[0], Bytes);
      Dec(Size, Bytes);
      Inc(Pos, Bytes);
    end;

    Done;
    HashResult := DigestAsBytes;
  finally
    ProtectBytes(Buffer);
    if Assigned(Progress) then
      Progress.OnProgress(Min, Max, Max);
  end;
end;

function TDECHash.CalcStream(const Stream: TStream; Size: Int64;
  Format: TDECFormatClass; const Progress: IDECProgress): RawByteString;
var
  Hash: TBytes;
begin
  CalcStream(Stream, Size, Hash, Progress);
  Result := BytesToRawString(ValidFormat(Format).Encode(Hash));
end;

procedure TDECHash.CalcFile(const FileName: string; var HashResult: TBytes;
  const Progress: IDECProgress);
var
  S: TFileStream;
begin
  SetLength(HashResult, 0);
  S := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    CalcStream(S, S.Size, HashResult, Progress);
  finally
    S.Free;
  end;
end;

function TDECHash.CalcFile(const FileName: string; Format: TDECFormatClass;
  const Progress: IDECProgress): RawByteString;
var
  Hash: TBytes;
begin
  CalcFile(FileName, Hash, Progress);
  Result := BytesToRawString(ValidFormat(Format).Encode(Hash));
end;

class function TDECHash.MGF1(const Data; DataSize, MaskSize: Integer): TBytes;
// indexed Mask generation function, IEEE P1363 Working Group
// equal to KDF1 except without Seed
// RFC 2437 PKCS #1
begin
  Result := KDF1(Data, DataSize, NullStr, 0, MaskSize);
end;

class function TDECHash.MGF1(const Data: TBytes; MaskSize: Integer): TBytes;
begin
  Result := KDFInternal(Data[0], Length(Data), NullStr, 0, MaskSize, ktKDF1);
end;

class function TDECHash.KDF1(const Data; DataSize: Integer; const Seed;
  SeedSize, MaskSize: Integer): TBytes;
begin
  Result := KDFInternal(Data, DataSize, Seed, SeedSize, MaskSize, ktKDF1);
end;

class function TDECHash.KDF1(const Data, Seed: TBytes;
  MaskSize: Integer): TBytes;
begin
  if (Length(Seed) > 0) then
    Result := KDFInternal(Data[0], length(Data), Seed[0], length(Seed), MaskSize, ktKDF1)
  else
    Result := KDFInternal(Data[0], length(Data), NullStr, 0, MaskSize, ktKDF1);
end;

class function TDECHash.KDF2(const Data; DataSize: Integer; const Seed;
                             SeedSize, MaskSize: Integer): TBytes;
begin
  Result := KDFInternal(Data, DataSize, Seed, SeedSize, MaskSize, ktKDF2);
end;

class function TDECHash.KDF2(const Data, Seed: TBytes; MaskSize: Integer): TBytes;
begin
  if (length(Seed) > 0) then
    Result := KDFInternal(Data[0], Length(Data), Seed[0], Length(Seed), MaskSize, ktKDF2)
  else
    Result := KDFInternal(Data[0], Length(Data), NullStr, 0, MaskSize, ktKDF2);
end;

class function TDECHash.KDF3(const Data; DataSize: Integer; const Seed;
                             SeedSize, MaskSize: Integer): TBytes;
begin
  Result := KDFInternal(Data, DataSize, Seed, SeedSize, MaskSize, ktKDF3);
end;

class function TDECHash.KDF3(const Data, Seed: TBytes; MaskSize: Integer): TBytes;
begin
  if (length(Seed) > 0) then
    Result := KDFInternal(Data[0], Length(Data), Seed[0], Length(Seed), MaskSize, ktKDF3)
  else
    Result := KDFInternal(Data[0], Length(Data), NullStr, 0, MaskSize, ktKDF3);
end;

class function TDECHash.KDFInternal(const Data; DataSize: Integer; const Seed;
                             SeedSize, MaskSize: Integer; KDFType: TKDFType): TBytes;
var
  I, n,
  Rounds, DigestBytes : Integer;
  Dest                : PByteArray;
  Count               : UInt32;
  HashInstance        : TDECHash;
begin
  SetLength(Result, 0);
  DigestBytes := DigestSize;
  Assert(MaskSize >= 0);
  Assert(DataSize >= 0);
  Assert(SeedSize >= 0);
  Assert(DigestBytes >= 0);

  HashInstance := TDECHashstype(self).Create;
  try
    Rounds := (MaskSize + DigestBytes - 1) div DigestBytes;
    SetLength(Result, Rounds * DigestBytes);
    Dest := @Result[0];


    if (KDFType = ktKDF2) then
      n := 1
    else
      n := 0;

    for I := 0 to Rounds-1 do
    begin
      Count := SwapUInt32(n);
      HashInstance.Init;

      if (KDFType = ktKDF3) then
      begin
        HashInstance.Calc(Count, SizeOf(Count));
        HashInstance.Calc(Data, DataSize);
      end
      else
      begin
        HashInstance.Calc(Data, DataSize);
        HashInstance.Calc(Count, SizeOf(Count));
      end;

      HashInstance.Calc(Seed, SeedSize);
      HashInstance.Done;
      Move(HashInstance.Digest[0], Dest[(I) * DigestBytes], DigestBytes);

      inc(n);
    end;

    SetLength(Result, MaskSize);
  finally
    HashInstance.Free;
  end;
end;

class function TDECHash.KDFx(const Data; DataSize: Integer; const Seed; SeedSize, MaskSize: Integer; Index: UInt32 = 1): TBytes;
// DEC's own KDF, even stronger
var
  I, J         : Integer;
  Count        : UInt32;
  R            : Byte;
  HashInstance : TDECHash;
begin
  Assert(MaskSize >= 0);
  Assert(DataSize >= 0);
  Assert(SeedSize >= 0);
  Assert(DigestSize > 0);

  SetLength(Result, MaskSize);
  Index := SwapUInt32(Index);

  HashInstance := TDECHashstype(self).Create;
  try
    for I := 0 to MaskSize - 1 do
    begin
      HashInstance.Init;

      Count := SwapUInt32(I);
      HashInstance.Calc(Count, SizeOf(Count));
      HashInstance.Calc(Result[0], I);

      HashInstance.Calc(Index, SizeOf(Index));

      Count := SwapUInt32(SeedSize);
      HashInstance.Calc(Count, SizeOf(Count));
      HashInstance.Calc(Seed, SeedSize);

      Count := SwapUInt32(DataSize);
      HashInstance.Calc(Count, SizeOf(Count));
      HashInstance.Calc(Data, DataSize);

      HashInstance.Done;

      R := 0;

      for J := 0 to DigestSize - 1 do
        R := R xor HashInstance.Digest[J];

      Result[I] := R;
    end;
  finally
    HashInstance.Free;
  end;
end;

class function TDECHash.KDFx(const Data, Seed: TBytes; MaskSize: Integer; Index: UInt32 = 1): TBytes;
begin
  if (length(Seed) > 0) then
    Result := KDFx(Data[0], Length(Data), Seed[0], Length(Seed), MaskSize, Index)
  else
    Result := KDFx(Data[0], Length(Data), NullStr, Length(Seed), MaskSize, Index)
end;

class function TDECHash.MGFx(const Data; DataSize, MaskSize: Integer; Index: UInt32 = 1): TBytes;
begin
  Result := KDFx(Data, DataSize, NullStr, 0, MaskSize, Index);
end;

class function TDECHash.MGFx(const Data: TBytes; MaskSize: Integer; Index: UInt32 = 1): TBytes;
begin
  Result := KDFx(Data[0], Length(Data), NullStr, 0, MaskSize, Index);
end;

{$IFDEF DELPHIORBCB}
procedure ModuleUnload(Instance: NativeInt);
var // automaticaly deregistration/releasing
  i: Integer;
begin
  if TDECHash.ClassList <> nil then
  begin
    for i := TDECHash.ClassList.Count - 1 downto 0 do
    begin
      if NativeInt(FindClassHInstance(TClass(TDECHash.ClassList[i]))) = Instance then
        TDECHash.ClassList.Remove(TDECFormat.ClassList[i].Identity);
    end;
  end;
end;
{$ENDIF DELPHIORBCB}

initialization
  // Code for packages and dynamic extension of the class registration list
  {$IFDEF DELPHIORBCB}
  AddModuleUnloadProc(ModuleUnload);
  {$ENDIF DELPHIORBCB}

  TDECHash.ClassList := TDECClassList.Create;

finalization
  // Ensure no further instances of classes registered in the registration list
  // are possible through the list after this unit has been unloaded by unloding
  // the package this unit is in
  {$IFDEF DELPHIORBCB}
  RemoveModuleUnloadProc(ModuleUnload);
  {$ENDIF DELPHIORBCB}

  TDECHash.ClassList.Free;
end.
