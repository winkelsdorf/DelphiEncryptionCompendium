// Simple project group for easier DEC 6.0 development
// (c) 2016 Markus Humm
program DEC60;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  DECBaseClass in 'DECBaseClass.pas',
  DECCipherBase in 'DECCipherBase.pas',
  DECCipherFormats in 'DECCipherFormats.pas',
  DECCipherModes in 'DECCipherModes.pas',
  DECCipherInterface in 'DECCipherInterface.pas',
  DECCiphers in 'DECCiphers.pas',
  DECCRC in 'DECCRC.pas',
  DECData in 'DECData.pas',
  DECDataCipher in 'DECDataCipher.pas',
  DECDataHash in 'DECDataHash.pas',
  DECFormat in 'DECFormat.pas',
  DECFormatBase in 'DECFormatBase.pas',
  DECHash in 'DECHash.pas',
  DECHashBase in 'DECHashBase.pas',
  DECHashInterface in 'DECHashInterface.pas',
  DECRandom in 'DECRandom.pas',
  DECTypes in 'DECTypes.pas',
  DECUtil in 'DECUtil.pas',
  DECUtilRawByteStringHelper in 'DECUtilRawByteStringHelper.pas';

begin
  try
    { TODO -oUser -cConsole Main : Insert code here }
  except
    on E: Exception do
      WriteLn(E.ClassName, ': ', E.Message);
  end;
end.

