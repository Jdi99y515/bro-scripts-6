@load base/files/extract

#Change this location to dump the extracted files to your own location.
#redef FileExtract::prefix = "./extract_files";

#Rename the file extentions so you know their type by first look.
global ext_map: table[string] of string = {
    ["application/x-dosexec"] = "exe",
    ["text/plain"] = "txt",
    ["image/jpeg"] = "jpg",
    ["image/png"] = "png",
    ["text/html"] = "html",
    ["application/msword"] = "doc",
    ["application/x-shockwave-flash"] = "swf",
    ["application/pdf"] = "pdf",
    ["application/jar"] = "jar",
    ["application/vnd.ms-cab-compressed"] = "cab",
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = "pptx",
} &default ="";

event file_sniff(f: fa_file, meta: fa_metadata)
{
    if ( ! meta?$mime_type )
        return;

    if ( meta$mime_type in ext_map )
    {
        local fname = fmt("./%s-%s.%s", f$source, f$id, ext_map[meta$mime_type]);
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    }
}
