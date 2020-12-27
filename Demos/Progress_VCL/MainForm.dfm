object FormMain: TFormMain
  Left = 0
  Top = 0
  Caption = 'ProgressTest'
  ClientHeight = 111
  ClientWidth = 635
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  DesignSize = (
    635
    111)
  PixelsPerInch = 96
  TextHeight = 13
  object Button1: TButton
    Left = 8
    Top = 16
    Width = 75
    Height = 25
    Caption = 'Encrypt'
    TabOrder = 0
    OnClick = Button1Click
  end
  object Edit1: TEdit
    Left = 104
    Top = 18
    Width = 523
    Height = 21
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 1
    Text = 'D:\Test.txt'
  end
  object ProgressBar1: TProgressBar
    Left = 8
    Top = 64
    Width = 619
    Height = 17
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 2
  end
end
