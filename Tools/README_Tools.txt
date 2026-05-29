================================================================================
  WINDOWS DFIR TOOLKIT v3.1 - TOOLS DIRECTORY
================================================================================

This folder contains third-party forensic tools required by certain scripts.
All tools must be placed here before running the corresponding scripts.

--------------------------------------------------------------------------------
WINPMEM - Live RAM Acquisition Tool
--------------------------------------------------------------------------------
Required by : Scripts\Memory\RAM_Dump.ps1
Download    : https://github.com/Velocidex/WinPmem/releases/latest
File needed : winpmem_mini_x64.exe  (64-bit systems)
              winpmem_mini_x86.exe  (32-bit systems)
License     : Apache 2.0 - Free for all use including commercial IR

DOWNLOAD STEPS:
  1. Go to: https://github.com/Velocidex/WinPmem/releases/latest
  2. Download: winpmem_mini_x64.exe
  3. Place it in this Tools\ folder
  4. Run: .\Run_IR_Collection.ps1 -Phase Memory
     OR:  .\Scripts\Memory\RAM_Dump.ps1

NOTE: The RAM_Dump.ps1 script will automatically attempt to download
      WinPmem from GitHub if it is not found in this folder.
      Requires internet access for auto-download.

--------------------------------------------------------------------------------
FOLDER STRUCTURE
--------------------------------------------------------------------------------
dfir-v3\
  Tools\
    winpmem_mini_x64.exe   <-- Place here
    winpmem_mini_x86.exe   <-- Optional for 32-bit
    README_Tools.txt       <-- This file

================================================================================
