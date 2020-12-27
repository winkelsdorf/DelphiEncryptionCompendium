{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License. A copy of this licence is found in the root directory of
  this project in the file LICENCE.txt or alternatively at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*****************************************************************************}

{$M+} // DUnitX would add it anyway
unit TestDECBaseClass;

// Needs to be included before any other statements
{$INCLUDE TestDefines.inc}

interface

uses
  System.SysUtils, System.Classes, Generics.Collections,
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ELSE}
  TestFramework,
  {$ENDIF}
  DECBaseClass, DECFormat, DECCiphers;

type
  // Test methods for class TDECClassList
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECClassList = class(TTestCase)
  strict private
    FDECClassList: TDECClassList;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestClassByName;
    procedure TestClassByIdentity;
    procedure TestGetClassList;
  end;

  // Test methods for class TDECObject
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECObject = class(TTestCase)
  strict private
    FDECObject: TDECObject;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestIdentity;
    procedure TestRegisterClass;
    procedure TestUnregisterClass;
    procedure TestGetShortClassNameFromName;
    procedure TestGetShortClassNameFromName2;
    procedure TestGetShortClassName;
    procedure TestGetShortClassName2;
  end;

implementation

procedure TestTDECClassList.SetUp;
begin
  FDECClassList := TDECClassList.Create;

  FDECClassList.Add(TFormat_HEX.Identity, TFormat_HEX);
  FDECClassList.Add(TFormat_HEXL.Identity, TFormat_HEXL);
  FDECClassList.Add(TFormat_DECMIME32.Identity, TFormat_DECMIME32);
  FDECClassList.Add(TFormat_Base64.Identity, TFormat_Base64);
  FDECClassList.Add(TFormat_UU.Identity, TFormat_UU);
  FDECClassList.Add(TFormat_XX.Identity, TFormat_XX);
  FDECClassList.Add(TFormat_ESCAPE.Identity, TFormat_ESCAPE);
end;

procedure TestTDECClassList.TearDown;
begin
  FDECClassList.Free;
  FDECClassList := nil;
end;

procedure TestTDECClassList.TestClassByIdentity;
var
  ReturnValue: TDECClass;
begin
  ReturnValue := FDECClassList.ClassByIdentity(TFormat_HEX.Identity);
  CheckEquals(ReturnValue, TFormat_HEX);
  CheckNotEquals(ReturnValue = TFormat_HEXL, true);

  ReturnValue := FDECClassList.ClassByIdentity(TFormat_Base64.Identity);
  CheckEquals(ReturnValue, TFormat_Base64);

  ReturnValue := FDECClassList.ClassByIdentity(TFormat_ESCAPE.Identity);
  CheckEquals(ReturnValue, TFormat_ESCAPE);
end;

procedure TestTDECClassList.TestClassByName;
var
  ReturnValue: TDECClass;
begin
  ReturnValue := FDECClassList.ClassByName('TFormat_HEX');
  CheckEquals(ReturnValue, TFormat_HEX);

  ReturnValue := FDECClassList.ClassByName('TFormat_hex');
  CheckEquals(ReturnValue, TFormat_HEX);

  ReturnValue := FDECClassList.ClassByName('TFormat_HEXL');
  CheckEquals(ReturnValue, TFormat_HEXL);

  ReturnValue := FDECClassList.ClassByName('TFormat_ESCAPE');
  CheckEquals(ReturnValue, TFormat_ESCAPE);
end;

procedure TestTDECClassList.TestGetClassList;
var
  sl : TStringList;
begin
  sl := TStringList.Create;
  try
    FDECClassList.GetClassList(sl);

    CheckEquals(sl.Count, 7, 'Wrong number of registered classes');
    CheckEquals(sl.IndexOf('TFormat_HEX')       >= 0, true);
    CheckEquals(sl.IndexOf('TFormat_HEXL')      >= 0, true);
    CheckEquals(sl.IndexOf('TFormat_DECMIME32') >= 0, true);
    CheckEquals(sl.IndexOf('TFormat_Base64')    >= 0, true);
    CheckEquals(sl.IndexOf('TFormat_UU')        >= 0, true);
    CheckEquals(sl.IndexOf('TFormat_XX')        >= 0, true);
    CheckEquals(sl.IndexOf('TFormat_ESCAPE')    >= 0, true);
  finally
    sl.Free;
  end;
end;

procedure TestTDECObject.TestGetShortClassName;
begin
  CheckEquals(TFormat_HEXL.GetShortClassName,
              'HEXL');
end;

procedure TestTDECObject.TestGetShortClassName2;
begin
  CheckEquals(TCipher_Skipjack.GetShortClassName,
              'Skipjack');
end;

procedure TestTDECObject.TestGetShortClassNameFromName;
begin
  CheckEquals(TDECClass.GetShortClassNameFromName('TFormat_HEXL'),
              'HEXL');
end;

procedure TestTDECObject.TestGetShortClassNameFromName2;
begin
  CheckEquals(TDECClass.GetShortClassNameFromName('TCipher_Skipjack'),
              'Skipjack');
end;

procedure TestTDECObject.SetUp;
begin
  FDECObject := TDECObject.Create;
end;

procedure TestTDECObject.TearDown;
begin
  FDECObject.Free;
  FDECObject := nil;
end;

procedure TestTDECObject.TestIdentity;
var
  ReturnValue: Int64;
begin
  // We do test the normal identity format, not the "special" one from DEC V5.2
  ReturnValue := FDECObject.Identity;
  CheckEquals(3520275915, ReturnValue, 'Wrong Identity Value');

  ReturnValue := TFormat_Hex.Identity;
  CheckEquals(3786628779, ReturnValue, 'Wrong Identity Value');
end;

procedure TestTDECObject.TestRegisterClass;
var
  ClassList   : TDECClassList;
  ReturnValue : Boolean;
begin
  ClassList := TDECClassList.Create(4);
  try
    FDECObject.RegisterClass(ClassList);

    ReturnValue := ClassList.ContainsValue(TDECObject);
    CheckEquals(true, ReturnValue, 'Class TDECObject has not been registered in class list');

    CheckEquals(1, ClassList.Count, 'Invalid number of registered classes');

    TFormat_HEX.RegisterClass(ClassList);

    ReturnValue := ClassList.ContainsValue(TFormat_HEX);
    CheckEquals(true, ReturnValue, 'Class TFormat_HEX has not been registered in class list');

    ReturnValue := ClassList.ContainsValue(TDECObject);
    CheckEquals(true, ReturnValue, 'Class TDECObject has not been registered in class list');

    CheckEquals(2, ClassList.Count, 'Invalid number of registered classes');
  finally
    ClassList.Free;
  end;
end;

procedure TestTDECObject.TestUnregisterClass;
var
  ClassList   : TDECClassList;
  ReturnValue : Boolean;
begin
  ClassList := TDECClassList.Create(4);
  try
    FDECObject.RegisterClass(ClassList);
    TFormat_HEX.RegisterClass(ClassList);

    CheckEquals(2, ClassList.Count, 'Invalid number of registered classes');

    FDECObject.UnregisterClass(ClassList);

    ReturnValue := ClassList.ContainsValue(TFormat_HEX);
    CheckEquals(true, ReturnValue, 'Wrong class has ben deregistered from class list');

    CheckEquals(1, ClassList.Count, 'Invalid number of registered classes');
  finally
    ClassList.Free;
  end;
end;

initialization
  // Register any test cases with the test runner
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TestTDECClassList);
  TDUnitX.RegisterTestFixture(TestTDECObject);
  {$ELSE}
  RegisterTests('DECBaseClass', [TestTDECClassList.Suite, TestTDECObject.Suite]);
  {$ENDIF}
end.

