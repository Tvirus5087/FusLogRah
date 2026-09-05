# FusLogRah
Utility intended to help identify audio files that are likely to produce XAudio2_7.dll crashes in Skyrim (SE/AE) and recommend or attempt fixes.

XAudioScan
==========

Finds Skyrim Special Edition audio files that XAudio2 can't play - the kind
that show up in a crash log as a fault inside XAudio2_7.dll. Optionally
builds a folder of repaired copies you can install as an override mod. 
AUDIO WILL SOUND DIFFERENT

This is a test build. Please read "Known limits" and "Reporting problems"
at the bottom.


WHAT IT IS
----------
A single .exe. No installer, no dependencies, no changes to your game.
It does not need SKSE and it does not run while Skyrim is running.

It only ever READS your mod files. The only thing it writes is the report
file and, if you ask for it, the override folder.


HOW TO RUN IT
-------------
Double-click XAudioScan.exe. It will ask you a few questions:

  1. Which folder to scan. Your Data folder, or - better if you use Mod
     Organizer 2 - your "mods" folder, which checks every mod at once.
     You can drag the folder onto the window instead of typing the path.

  2. Whether to build an override folder with repaired copies.

  3. Where to put it, if you said yes.

  4. Whether to downmix stereo Sound\FX files to mono, and whether to
     replace unrecoverable files with silence. Both default to no.

When it finishes you get XAudioScan_Report.txt next to the exe.

Windows may show a blue "Windows protected your PC" box the first time,
because this is an unsigned exe from an unknown publisher. Click "More
info" then "Run anyway" if you're comfortable doing so. Some antivirus
software also flags small unsigned tools like this; that's a false
positive, but you should only run it if you trust where you got it.


READING THE REPORT
------------------
  [WILL CRASH]  Breaks a hard XAudio2 rule. This is the one that matters.
  [SUSPICIOUS]  Legal, but a known source of trouble.

Each entry says what's wrong and how to fix it properly.


USING THE OVERRIDE FOLDER
-------------------------
  1. Zip the folder. Sound\ and Music\ should be at the ROOT of the zip,
     not inside another folder.
  2. Install the zip with Mod Organizer 2 or Vortex like any other mod.
  3. Put it LAST in your load order so it wins every conflict.

Loose files always beat files packed inside a BSA, so this also overrides
broken audio that lives inside an archive.

Repairs only move audio between plain PCM formats - headers are rebuilt,
bit depths are converted. Nothing is re-encoded through a lossy codec, so
nothing is degraded beyond the bit-depth change itself.


WHAT IT CANNOT FIX
------------------
  - MP3, ADPCM or GSM audio inside a .wav
  - xWMA missing its dpds seek table (usually a .wma renamed to .xwm)

These need real re-encoding with an audio tool. The report names them so
you can ask the mod author, or fix them yourself in Audacity by exporting
as WAV with "Signed 16-bit PCM" encoding.

The "replace with silence" option covers these by making them play nothing
instead of crashing. It's off by default because quietly losing a sound is
its own kind of bad.


KNOWN LIMITS
------------
  - Skyrim Special Edition only. Skyrim LE archives (BSA v103/v104) are
    reported and skipped, not scanned.
  - Compressed BSA entries are decompressed with a hand-written LZ4
    decoder. It has been tested against constructed archives but not
    widely against real ones. If the summary line shows decompression
    failures, that's the first thing to suspect. Extra a particular mod 
    with CAO or BSA Extractor and rerun on that folder
  - If two mods contain the same broken file, the first one scanned is
    the one repaired. The report notes each skip.
  - A crash inside XAudio2_7.dll is not always caused by a bad file.
    Voice exhaustion and audio device changes cause it too, and this tool
    won't help with those.


COMMAND LINE
------------
Run "XAudioScan.exe --help" for flags if you'd rather script it than use
the prompts.


REPORTING PROBLEMS
------------------
Please include:

  - XAudioScan_Report.txt
  - What you pointed it at (Data folder? MO2 mods folder?)
  - Your Skyrim version and whether you use MO2 or Vortex
  - If a repaired file sounded wrong: which file, and what it sounded like
  - If it crashed or hung: what was on screen when it stopped

The most useful reports are ones where the tool said a file was fine and
it still crashed, or where a repaired file played back wrong. Both mean
something in the checking logic is off.
