
       Client                                           Server

Key  ^ HelloPacket
Exch | + public key
     v                         -------->
                                                  HelloPacket  ^ Key
                                                + public key   | Exch
                               <--------                       v
       [AppDataPackets]        <------->       [AppDataPackets]

