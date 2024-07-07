rule Dropper_DownloadFromURL  {
    
    meta: 
        description = "Yara rule to help detecting Dropper.DownloadFromURL"
        date = "2024-07-07"
        author = "str4int"
        reference_url = "https://github.com/str4int/Threat-Chronicles/blob/f2103108a38084971803098e1e42516ba7a9bb11/Dropper.DownloadFromURL%20.pdf"

    strings:
        $string1 = "ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q" wide
	$string2 = "CR433101.dat.exe" wide
        $PE_magic_byte = "MZ"
        $sus_hex_string = { 43 00 3A 00 5C 00 55 00 73 00 65 00 72 00 73 00 5C 00 50 00 75 00 62 00 6C 00 69 00 63 00 5C 00 44 00 6F 00 63 00 75 00 6D 00 65 00 6E 00 74 00 73 00 5C 00 43 00 52 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2E 00 64 00 61 00 74 00 2E 00 65 00 78 00 65 }

    condition:
        $PE_magic_byte at 0 and //$string1 or $string2 or $string3
        ($string1 and $string2) or
        $sus_hex_string
}

/*
         .::                                  .::  
         .::             .::     .:           .::  
 .:::: .:.: .:.: .:::  . .::       .:: .::  .:.: .:
.::      .::   .::    .: .::    .:: .::  .::  .::  
  .:::   .::   .::  .::  .::    .:: .::  .::  .::  
    .::  .::   .:: .:::: .: .:: .:: .::  .::  .::  
.:: .::   .:: .:::       .::    .::.:::  .::   .::

*/
