program DECDUnitTestSuite;

{

  Delphi DUnit Test Project
  -------------------------
  This project contains the DUnit test framework and the GUI/Console test runners.
  Add "CONSOLE_TESTRUNNER" to the conditional defines entry in the project options
  to use the console test runner.  Otherwise the GUI test runner will be used by
  default.

}

{$IFDEF CONSOLE_TESTRUNNER}
{$APPTYPE CONSOLE}
{$ENDIF}

uses
  Vcl.Forms,
  TestFramework,
  GUITestRunner,
  TextTestRunner,
  TestDECUtil in 'Tests\TestDECUtil.pas',
  TestDECFormatBase in 'Tests\TestDECFormatBase.pas',
  TestDECFormat in 'Tests\TestDECFormat.pas',
  TestDECHash in 'Tests\TestDECHash.pas',
  TestDECHashKDF in 'Tests\TestDECHashKDF.pas',
  TestDECCRC in 'Tests\TestDECCRC.pas',
  TestDECCipher in 'Tests\TestDECCipher.pas',
  TestDECRandom in 'Tests\TestDECRandom.pas',
  TestDECCipherModes in 'Tests\TestDECCipherModes.pas',
  TestDECBaseClass in 'Tests\TestDECBaseClass.pas',
  TestDECTestDataContainer in 'Tests\TestDECTestDataContainer.pas',
  TestDECCipherFormats in 'Tests\TestDECCipherFormats.pas';

{$R *.RES}

begin
  ReportMemoryLeaksOnShutdown := True;
  Application.Initialize;
  if IsConsole then
    TextTestRunner.RunRegisteredTests.Free
  else
    GUITestRunner.RunRegisteredTests;
end.

