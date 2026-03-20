# Start-Process -NoNewWindow ensures hello.exe inherits the console directly
# rather than being piped through PowerShell's output pipeline.  This is
# required under Wine where the Windows console object is not connected to
# Unix stdout for child processes invoked via the & operator.
Start-Process -FilePath "Z:\mnt\work\hello.exe" -NoNewWindow -Wait
