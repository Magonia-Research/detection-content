rule eSXI_Ransomware {
   meta:
      description = "linux_ransomware - file DarkSide_BlackMatter"
      author = "signalblur"
      reference = "Linux Research"
      date = "2023-07-17"
      DarkSide_BlackMatter_hash1 = "6a7b7147fea63d77368c73cef205eb75d16ef209a246b05698358a28fd16e502"
      HelloKitty_hash2 = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"
      Conti_hash3 = "8b57e96e90cd95fc2ba421204b482005fe41c28f506730b6148bcef8316a3201"
   strings:
      $a1 = "Unable To Get Process List" ascii
      $a2 = "app::esxi_utils::get_process_list" ascii
      $a3 = "app::master_proc::process_file_encryption" ascii
      $a4 = "app::file_encrypter::process_file" ascii
      $a5 = "execvp failure" ascii

      $e1 = "esxcli vm process kill" ascii
      $e2 = "esxcli vm process list" ascii
      $e3 = "esxcli --formatter=csv" ascii
      $e4 = "error encrypt: %s rename back:%s" fullword ascii
      $e5 = "vm process kill --type=force" ascii

      $r1 = "Download TOR Browser" ascii
      $r2 = "We offer you to purchase special decryption software" ascii
      $r3 = "Using silent mode, if you on esxi - stop VMs manualy" fullword ascii
      $r4 = "File [%s] was encrypted" fullword ascii
      $r5 = "File [%s] was NOT encrypted" fullword ascii
      $r6 = " without --path encrypts current dir" fullword ascii
      $r7 = "All of your files are currently encrypted by CONTI strain" ascii
      $r8 = "DON'T TRY TO IGNORE" ascii
      $r9 = "DONT'T TRY TO RECOVER" ascii

   condition:
      uint16(0) == 0x457f and filesize < 6000KB and
      2 of them
}

rule BlackBasta {
   meta:
      description = "linux_ransomware - file BlackBasta"
      author = "signalblur"
      reference = "Linux Research"
      date = "2023-07-17"
      hash1 = "96339a7e87ffce6ced247feb9b4cb7c05b83ca315976a9522155bad726b8e5be"
   strings:
      $s1 = "Input is not valid base64-encoded data." fullword ascii
      $s2 = "download and install TOR browser first https://torproject.org" fullword ascii
      $s3 = "readmeContent" fullword ascii
      $s4 = "_Z16EncryptionThreadv" fullword ascii
      $s5 = "C:/Users/dssd/Desktop/src" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      3 of them
}

rule DarkSide_BlackMatter {
   meta:
      description = "linux_ransomware - file DarkSide_BlackMatter"
      author = "signalblur"
      reference = "Linux Research"
      date = "2023-07-17"
      hash1 = "6a7b7147fea63d77368c73cef205eb75d16ef209a246b05698358a28fd16e502"
   strings:
      $s1 = "Unable To Get Process List, " ascii
      $s2 = "app::esxi_utils::get_process_list" ascii
      $s3 = "app::master_proc::process_file_encryption" ascii
      $s4 = "app::file_encrypter::process_file" ascii
      $s5 = "execvp failure" ascii
   condition:
      uint16(0) == 0x457f and filesize < 6000KB and
      3 of them
}

rule BlackSuit {
   meta:
      description = "linux_ransomware - file BlackSuit"
      author = "signalblur"
      reference = "Linux Research"
      date = "2023-07-17"
      hash1 = "1c849adcccad4643303297fb66bfe81c5536be39a87601d67664af1d14e02b9e"
   strings:
      $e1 = "esxcli vm process kill" ascii
      $e2 = "esxcli vm process list" ascii
      
      $r1 = "blacksuit" ascii
      $r2 = "BlackSuit" ascii

      $w1 = "Terned off vmsyslog" ascii
      $w2 = "ps -Cc|grep vmsyslogd > PS_syslog_" ascii
      $w3 = "Entropy collected!" ascii
      $w4 = "Drop readme failed: %s(%d)" ascii
   condition:
    uint16(0) == 0x457f and
    filesize < 8000KB and
    (1 of ($e*) or 1 of ($r*) or 2 of ($w*))
}

rule Cylance {
   meta:
      description = "linux_ransomware - file Cylance"
      author = "signalblur"
      reference = "Linux Research"
      date = "2023-07-17"
      hash1 = "d1ba6260e2c6bf82be1d6815e19a1128aa0880f162a0691f667061c8fe8f1b2c"
   strings:
      $s1 = "Usage: %s /path/to/be/encrypted" fullword ascii
      $s2 = "Unexpected error %d on netlink descriptor %d (address family %d)." fullword ascii
      $s3 = "you will lose your time and data" ascii
      $s4 = "@onionmail.com" fullword ascii
      $s5 = "relocation processing: %s%s" fullword ascii
      $s6 = "Its just a business." ascii

   condition:
      uint16(0) == 0x457f and filesize < 3000KB and
      4 of them
}

rule HelloKitty {
   meta:
      description = "linux_ransomware - file HelloKitty"
      author = "signalblur"
      reference = "Linux Research"
      date = "2023-07-17"
      hash1 = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"
   strings:
      $s3 = "esxcli vm process kill" ascii
      $s4 = "work.log" ascii
      $s7 = "esxcli vm process list" fullword ascii
      $s8 = "Error InitAPI !!!" fullword ascii
      $s9 = "error encrypt: %s rename back:%s" fullword ascii
      $s10 = "No Files Found !!!" fullword ascii
      $s11 = "%d manual !!!" fullword ascii
      $s12 = "Log closed :%s" fullword ascii
      $s13 = "%ld - Files Found  " fullword ascii
      $s15 = "Total VM run on host:" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      4 of them
}

rule RedAlert {
   meta:
      description = "linux_ransomware - file RedAlert"
      author = "signalblur"
      reference = "Linux Research"
      date = "2023-07-17"
      hash1 = "039e1765de1cdec65ad5e49266ab794f8e5642adb0bdeb78d8c0b77e8b34ae09"
   strings:
      $s1 = "esxcli --formatter=csv" ascii
      $s2 = "vm process list | tail -n +2" ascii
      $s3 = "Run command for stop all running VM`s." fullword ascii
      $s4 = "vm process kill" fullword ascii
      $s5 = "# ATTENTION the argument given first will be used for target(file or path)" fullword ascii
      $s6 = "search and encryption will include subdirectories" ascii
      $s9 = "Download TOR Browser" ascii
      $s10 = "[info] Execution time check: %f" fullword ascii
      $s11 = "Encryption is reverssible process" ascii
      $s15 = "Run command for stop all running VM`s" ascii
      $s16 = "[info] File: %s/%s, begin encryption" fullword ascii
      $s17 = "Don't modify contents of the encrypted files" ascii
      $s18 = "We offer you to purchase special decryption software, payment includes decryptor, key for it and erasure of stolen data" fullword ascii
      $s19 = "DumpHex" fullword ascii
      $s20 = "On our webpage you will be able to purchase decryptor, chat with our support and decrypt few files for free" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 1000KB and
      5 of them
}

rule Sodinokibi {
   meta:
      description = "linux_ransomware - file Sodinokib"
      author = "signalblur"
      reference = "Linux Research"
      date = "2023-07-17"
      hash1 = "a322b230a3451fd11dcfe72af4da1df07183d6aaf1ab9e062f0e6b14cf6d23cd"
   strings:
      $s1 = "Usage example: elf.exe --path /vmfs/ --threads 5 " fullword ascii
      $s2 = "uname -a && echo \" | \" && hostname" fullword ascii
      $s3 = "esxcli --formatter=csv" ascii
      $s4 = "vm process list | awk -F" ascii
      $s5 = "!!!BY DEFAULT THIS SOFTWARE USES 50 THREADS!!!" fullword ascii
      $s6 = "[%s] already encrypted" fullword ascii
      $s7 = "%d:%d: Comment not allowed here" fullword ascii
      $s11 = "without --path encrypts current dir" ascii
      $s17 = "File [%s] was NOT encrypted" fullword ascii
      $s19 = "Using silent mode, if you on esxi - stop VMs manualy" ascii
      $s20 = "File [%s] was encrypted" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      4 of them
}

rule Conti {
   meta:
      description = "linux_ransomware - file Conti"
      author = "signalblur"
      reference = "Linux Research"
      date = "2023-07-17"
      hash1 = "8b57e96e90cd95fc2ba421204b482005fe41c28f506730b6148bcef8316a3201"
   strings:
      $s1 = "Something went wrong! - InitializeEncryptor " fullword ascii
      $s2 = "Something went wrong! - RSA_public_encrypt!" fullword ascii
      $s3 = "Process with PID %d was killed" fullword ascii
      $s4 = "./locker --path /path" ascii
      $s5 = "To prove that we REALLY CAN get your data back" ascii
      $s6 = "Starting encryption - CONTI POC" ascii
      $s9 = "All of your files are currently encrypted" ascii
      $s11 = "download and install TOR browser" ascii
      $s12 = "DON'T TRY TO IGNORE us" ascii
      $s13 = "DONT'T TRY TO RECOVER" ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      4 of them
}

rule GonnaCry {
   meta:
      description = "linux_ransomware - file GonnaCry"
      author = "signalblur"
      reference = "Linux Research"
      date = "2023-07-17"
      hash1 = "f5de75a6db591fe6bb6b656aa1dcfc8f7fe0686869c34192bfa4ec092554a4ac"
   strings:
      $s1 = "read_from_file_encrypted_files" fullword ascii
      $s2 = "get_username" fullword ascii
      $s4 = "KEY = %s IV = %s PATH = %s" fullword ascii
      $s7 = "get_desktop_enviroment" fullword ascii
      $s8 = "Sup brother, all your files below have been encrypted, cheers!" fullword ascii
      $s11 = "encrypt_files" fullword ascii
      $s12 = "get_test_path" fullword ascii
      $s14 = "get_filename_ext" fullword ascii
      $s15 = "save_into_file_encrypted_list" fullword ascii
      $s16 = "get_home_enviroment" fullword ascii
      $s17 = "doc docx xls xlsx ppt pptx pst ost msg eml vsd vsdx txt csv rtf wks wk1 pdf dwg onetoc2 snt jpeg jpg docb docm dot dotm dotx xls" ascii
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      5 of them
}

rule Polaris {
   meta:
      description = "linux_ransomware - file Polaris"
      author = "signalblur"
      reference = "Linux Research"
      date = "2023-07-17"
      hash1 = "e29aa629bf492a087a17fa7ec0edb6be4b84c5c8b0798857939d8824fa91dbf9"
   strings:
      $x1 = "Inf.css.gif.htm.jpg.mjs.pdf.png.svg.xml" ascii
      $x2 = ".avif.html.jpeg.json.ssh/.wasm.webp" ascii
      $x3 = "PolarisRadicalReferer" ascii
      $x4 = "WARNING.txt" ascii
      $x5 = "polaris" ascii
      $x6 = "@tutanota.com" ascii
      $x7 = "@opentrash.com" ascii
      $x8 = "pol.aris" ascii
      $x9 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" ascii
      
   condition:
      uint16(0) == 0x457f and filesize < 13000KB and
      4 of ($x*)
}

rule Royal {
   meta:
      description = "royal_linux - file Royal"
      author = "signalblur"
      reference = "Linux Research"
      date = "2023-07-17"
      hash1 = "b57e5f0c857e807a03770feb4d3aa254d2c4c8c8d9e08687796be30e2093286c"
   strings:
      $s1 = "esxcli vm process kill" fullword ascii
      $s2 = "If you are reading this, it means that your system were hit by Royal ransomware." ascii
      $s3 = "esxcli vm process list" ascii
      $s4 = ".onion" ascii
      $s5 = ".royal_u" ascii
      $s6 = ".royal_w" ascii
   condition:
      uint16(0) == 0x457f and filesize < 7000KB and
      2 of them
}

