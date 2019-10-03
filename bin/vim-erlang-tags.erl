#!/usr/bin/env escript
%% -*- tab-width: 4;erlang-indent-level: 4;indent-tabs-mode: nil -*-
%% ex: ts=4 sw=4 ft=erlang et

%%% Copyright 2013 Csaba Hoch
%%% Copyright 2013 Adam Rutkowski
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.

%%% Recommended reading:
%%%
%%% - http://ctags.sourceforge.net/FORMAT
%%% - http://vimdoc.sourceforge.net/htmldoc/tagsrch.html#tags-file-format

%%% The Tags ets table has the following scheme:
%%%
%%%     {{TagName, FilePath, Scope, Kind}, TagAddress}
%%%
%%% Or in more readable notation:
%%%
%%%     {TagName, FilePath, Scope, Kind} -> TagAddress
%%%
%%% Examples of entries (and the tags output generated from them):
%%%
%%%     {ErlFileName, FilePath, global, $F} -> TagAddress
%%%         myfile.erl  ./myfile.erl  1;"  F
%%%
%%%     {HrlFileName, FilePath, global, $F} -> TagAddress
%%%         myfile.hrl  ./myfile.hrl  1;"  F
%%%
%%%     {ModName, FilePath, global, $M} -> TagAddress
%%%         myfile  ./myfile.erl  1;"  M
%%%
%%%     {FuncName, FilePath, local, $f} -> TagAddress
%%%         f  ./mymod.erl  /^f\>/;"  f  file:
%%%
%%%     {FuncName, FilePath, global, $f} -> TagAddress
%%%         mymod:f  ./mymod.erl  /^f\>/;"  f
%%%
%%%     {Type, FilePath, local, $t} -> TagAddress
%%%         mytype  ./mymod.erl  /^-type\s\*\<mytype\>/;"  t  file:
%%%
%%%     {Type, FilePath, global, $t} -> TagAddress
%%%         mymod:mytype  ./mymod.erl  /^-type\s\*\<mytype\>/;"  t
%%%
%%%     {Record, FilePath, local, $r} -> TagAddress
%%%         myrec  ./mymod.erl  /^-record\s\*\<myrec\>/;"  r  file:
%%%
%%%     {Record, FilePath, global, $r} -> TagAddress
%%%         myrec  ./myhrl.hrl  /^-record\s\*\<myrec\>/;"  r
%%%
%%%     {Macro, FilePath, local, $d} -> TagAddress
%%%         mymac  ./mymod.erl  /^-define\s\*\<mymac\>/;"  d  file:
%%%
%%%     {Macro, FilePath, global, $d} -> TagAddress
%%%         mymac  ./myhrl.hrl  /^-define\s\*\<mymac\>/;"  d

-mode(compile).

-define(COMPILE, fun(Re) ->
                         {ok, CRE} = re:compile(Re, [multiline]),
                         CRE
                 end).

-define(RE_FUNCTIONS,  ?COMPILE("^([a-z][a-zA-Z0-9_@]*)\\s*\\(")).
-define(RE_TYPESPECS1, ?COMPILE("^-\\s*(type|opaque)\\s*([a-zA-Z0-9_@]+)\\b")).
-define(RE_TYPESPECS2, ?COMPILE("^-\\s*(type|opaque)\\s*'([^ \\t']+)'")).
-define(RE_DEFINES1,   ?COMPILE("^-\\s*(record|define)\\s*\\(?\\s*([a-zA-Z0-9_@]+)\\b")).
-define(RE_DEFINES2,   ?COMPILE("^-\\s*(record|define)\\s*\\(?\\s*'([^ \\t']+)'")).

-define(DEFAULT_PATH, ".").

-type args() ::
    #{include := list(),
      ignore := list(),
      output := list(),
      otp := list(),
      help := list()
     }.

-type config() ::
    #{explore := list(),
      output := string()
     }.

allowed_commands() ->
    [
     {include, ["-i", "--include", "--"]},
     {ignore,  ["-g", "--ignore"]},
     {output,  ["-o", "--output"]},
     {otp,     ["-p", "--otp"]},
     {verbose, ["-v", "--verbose"]},
     {help,    ["-h", "--help"]}
    ].

main(Args) ->
    Opts0 = reparse_arguments(Args),
    Opts = clean_opts(Opts0),
    run(Opts).

run(#{help := true}) ->
    print_help();
run(#{explore := Explore, output := TagFile}) ->
    Tags = create_tags(Explore),
    ok = tags_to_file(Tags, TagFile),
    ets:delete(Tags).

-spec reparse_arguments([string()]) -> args().
reparse_arguments(Args) ->
    EmptyOpts = #{include => [], ignore => [], output => [], otp => [], verbose => [], help => []},
    fill_args(EmptyOpts, Args).

-spec fill_args(args(), [string()]) -> args().
fill_args(Opts, []) ->
    Opts;
fill_args(Opts, [Arg | OtherArgs] = Args) ->
    {ok, Param, ParsedArgs} =
        case parse_arg(Arg) of
            {ok, P} -> {ok, P, OtherArgs};
            %% If the parameter is not recognised, just throw it into include
            {include, Arg} -> {ok, include, Args}
        end,
    {StateArgs, Rest} = get_full_arg_state(Param, ParsedArgs),
    fill_args(Opts#{Param := maps:get(Param, Opts, []) ++ StateArgs}, Rest).

-spec parse_arg(string()) -> {ok, atom()} | {include, term()} | {error, unrecognised_parameter}.
parse_arg(Arg) ->
    lists:foldl(
      fun({State, StateList}, Acc) ->
              case lists:member(Arg, StateList) of
                  true -> {ok, State};
                  _ -> Acc
              end
      end,
      {include, Arg}, %% If the parameter is not recognised, just throw it into include
      allowed_commands()).

-spec get_full_arg_state(atom(), [string()]) -> {[string()], [string()]}.
get_full_arg_state(S, Args) when S =:= otp; S =:= help; S =:= verbose ->
    {[], Args};
get_full_arg_state(S, Args) ->
    log("Parsing Args for State ~p~n", [S]),
    {StateArgs, _Rest} = Ret = consume_until_new_state(Args),
    case StateArgs of
        [] -> log_error("Arguments needed for ~s.~n", [S]);
        _ -> ok
    end,
    Ret.

-spec consume_until_new_state([string()]) -> {[string()], [string()]}.
consume_until_new_state(Args) ->
    log("Args are ~p~n", [Args]),
    States = lists:foldl(fun({_,S}, Acc) -> S ++ Acc end, [], allowed_commands()),
    lists:splitwith(
      fun("-" ++ _ = El) ->
              case lists:member(El, States) of
                  true -> false;
                  _ -> log_error("Unknown argument: ~s~n", [El]), halt(1)
              end;
         (El) ->
              not lists:member(El, States)
      end, Args).

-spec clean_opts(args()) -> config().
clean_opts(#{help := [_]}) ->
    #{help => true};
clean_opts(#{otp := ["true"], include := Inc} = Opts0) ->
    log("Including OTP in.~n"),
    AllIncludes = [code:lib_dir() | Inc],
    Opts1 = maps:update(include, AllIncludes, Opts0),
    Opts2 = maps:update(otp, [], Opts1),
    clean_opts(Opts2);
clean_opts(#{verbose := [_]} = Opts0) ->
    log("Verbose mode on.~n"),
    clean_opts(Opts0#{verbose := true});
clean_opts(#{output := []} = Opts0) ->
    log("Set output to default 'tags'.~n"),
    clean_opts(Opts0#{output := ["tags"]});
clean_opts(#{include := []} = Opts0) ->
    log("Set includes to default current dir.~n"),
    clean_opts(Opts0#{include := [?DEFAULT_PATH]});
clean_opts(#{include := Included, ignore := Ignored, output := [Output]}) ->
    log("Set includes to default current dir.~n"),
    #{explore => expand_includes_remove_ignored(Included, Ignored), output => Output}.

expand_includes_remove_ignored(Included, Ignored) ->
    AllIncluded = lists:foldl(fun(L,Acc) -> L++Acc end,[],expand_dirs(Included)),
    AllIgnored = lists:foldl(fun(L,Acc) -> L++Acc end,[],expand_dirs(Ignored)),
    lists:subtract(AllIncluded, AllIgnored).

-spec expand_dirs([string()]) -> [ [] | [file:filename()] ].
expand_dirs(Included) ->
    lists:map(
      fun(FileName) ->
              case filelib:is_file(FileName) of
                  false ->
                          log_error("FileName: ~p~n", [FileName]),
                          [];
                  _ ->
                      case filelib:is_dir(FileName) of
                          true ->
                              filelib:wildcard(FileName ++ "/**/*.{erl,hrl}");
                          _ -> FileName
                      end
              end
      end,
      Included).

%%%================================================================================================
%%% Create tags from directory trees and file lists
%%%================================================================================================

% Read the given Erlang source files and return an ets table that contains the appropriate tags.
create_tags(Explore) ->
    log("In create_tags, To explore: ~p~n", [Explore]),
    EtsTags = ets:new(tags, [set]),
    log("Tags table created.~n"),
    process_filenames(Explore, EtsTags),
    EtsTags.


% Go through the given files: scan the Erlang files for tags
% Here we now for sure that `Files` are indeed files with extensions *.erl or *.hrl.
process_filenames([], _Tags) ->
    ok;
process_filenames([File|OtherFiles], EtsTags) ->
    add_tags_from_file(File, EtsTags),
    process_filenames(OtherFiles, EtsTags).

%%%=============================================================================
%%% Scan a file or line for tags
%%%=============================================================================

% Read the given Erlang source file and add the appropriate tags to the Tags ets table.
add_tags_from_file(File, Tags) ->
    log("~nProcessing file: ~s~n", [File]),

    BaseName = filename:basename(File), % e.g. "mymod.erl"
    ModName = filename:rootname(BaseName), % e.g. "mymod"
    add_file_tag(Tags, File, BaseName, ModName),

    case file:read_file(File) of
        {ok, Contents} -> ok = scan_tags(Contents, {Tags, File, ModName});
        Err -> log_error("File ~s not readable: ~p~n", [File, Err])
    end.

scan_tags(Contents, {Tags, File, ModName}) ->
    scan_tags_core(
      Contents, ?RE_FUNCTIONS,
      fun([_, FuncName]) ->
              add_func_tags(Tags, File, ModName, FuncName)
      end),
    scan_tags_core(
      Contents, ?RE_TYPESPECS1,
      fun([_, Attr, TypeName]) ->
              InnerPattern = [TypeName, "\\>"],
              add_type_tags(Tags, File, ModName, Attr, TypeName, InnerPattern)
      end),
    scan_tags_core(
      Contents, ?RE_TYPESPECS2,
      fun([_, Attr, TypeName]) ->
              InnerPattern = [$', TypeName, $'],
              add_type_tags(Tags, File, ModName, Attr, TypeName, InnerPattern)
      end),
    scan_tags_core(
      Contents, ?RE_DEFINES1,
      fun([_, Attr, Name]) ->
              InnerPattern = [Name, "\\>"],
              add_record_or_macro_tag(Tags, File, Attr, Name, InnerPattern)
      end),
    scan_tags_core(
      Contents, ?RE_DEFINES2,
      fun([_, Attr, Name]) ->
              InnerPattern = [$', Name, $'],
              add_record_or_macro_tag(Tags, File, Attr, Name, InnerPattern)
      end),
    ok.

scan_tags_core(Contents, Pattern, Fun) ->
    case re:run(Contents, Pattern, [{capture, all, binary}, global]) of
        nomatch ->
            ok;
        {match, Matches} ->
            lists:foreach(Fun, Matches)
    end.

%%%=============================================================================
%%% Add specific tags
%%%=============================================================================

% Add this information to Tags.
add_file_tag(Tags, File, BaseName, ModName) ->

    % myfile.hrl <tab> ./myfile.hrl <tab> 1;"  F
    % myfile.erl <tab> ./myfile.erl <tab> 1;"  F
    % myfile <tab> ./myfile.erl <tab> 1;"  M
    add_tag(Tags, BaseName, File, "1", global, $F),

    case filename:extension(File) of
        ".erl" ->
            add_tag(Tags, ModName, File, "1", global, $M);
        _ ->
            ok
    end.

% File contains the function ModName:FuncName; add this information to Tags.
add_func_tags(Tags, File, ModName, FuncName) ->

    log("Function definition found: ~s~n", [FuncName]),

    % Global entry:
    % mymod:f <tab> ./mymod.erl <tab> /^f\>/
    add_tag(Tags, [ModName, ":", FuncName], File, ["/^", FuncName, "\\>/"],
            global, $f),

    % Static (or local) entry:
    % f <tab> ./mymod.erl <tab> /^f\>/ <space><space> ;" <tab> file:
    add_tag(Tags, FuncName, File, ["/^", FuncName, "\\>/"], local, $f).

% File contains the type ModName:Type; add this information to Tags.
add_type_tags(Tags, File, ModName, Attribute, TypeName, InnerPattern) ->

    log("Type definition found: ~s~n", [TypeName]),

    Pattern = ["/^-\\s\\*", Attribute, "\\s\\*", InnerPattern, $/],

    % Global entry:
    % mymod:mytype <tab> ./mymod.erl <tab> /^-type\s\*mytype\>/
    % mymod:mytype <tab> ./mymod.erl <tab> /^-opaque\s\*mytype\>/
    add_tag(Tags, [ModName, ":", TypeName], File, Pattern, global, $t),

    % Static (or local) entry:
    % mytype <tab> ./mymod.erl <tab> /^-type\s\*mytype\>/
    %     <space><space> ;" <tab> file:
    % mytype <tab> ./mymod.erl <tab> /^-opaque\s\*mytype\>/
    %     <space><space> ;" <tab> file:
    add_tag(Tags, TypeName, File, Pattern, local, $t).

% File contains a macro or record called Name; add this information to Tags.
add_record_or_macro_tag(Tags, File, Attribute, Name, InnerPattern) ->

    {Kind, Prefix} =
        case Attribute of
            <<"record">> ->
                log("Record found: ~s~n", [Name]),
                {$r, $#};
            <<"define">> ->
                log("Macro found: ~s~n", [Name]),
                {$d, $?}
        end,

    Scope =
        case filename:extension(File) of
            ".hrl" ->
                global;
            _ ->
                local
        end,

    % myrec  ./mymod.erl  /^-record\s\*\<myrec\>/;"  r  file:
    % myrec  ./myhrl.hrl  /^-record\s\*\<myrec\>/;"  r
    % mymac  ./mymod.erl  /^-define\s\*\<mymac\>/;"  m  file:
    % mymac  ./myhrl.hrl  /^-define\s\*\<mymac\>/;"  m
    add_tag(Tags, Name, File,
            ["/^-\\s\\*", Attribute, "\\s\\*(\\?\\s\\*", InnerPattern, "/"],
            Scope, Kind),

    % #myrec  ./mymod.erl  /^-record\s\*\<myrec\>/;"  r  file:
    % #myrec  ./myhrl.hrl  /^-record\s\*\<myrec\>/;"  r
    % ?mymac  ./mymod.erl  /^-define\s\*\<mymac\>/;"  m  file:
    % ?mymac  ./myhrl.hrl  /^-define\s\*\<mymac\>/;"  m
    add_tag(Tags, [Prefix|Name], File,
            ["/^-\\s\\*", Attribute, "\\s\\*(\\?\\s\\*", InnerPattern, "/"],
            Scope, Kind).

add_tag(Tags, Tag, File, TagAddress, Scope, Kind) ->
    ets:insert_new(Tags, {{Tag, File, Scope, Kind}, TagAddress}).

%%%=============================================================================
%%% Writing tags into a file
%%%=============================================================================

tags_to_file(Tags, TagsFile) ->
    Header = "!_TAG_FILE_SORTED\t1\t/0=unsorted, 1=sorted/\n",
    Entries = lists:sort( [ tag_to_binary(Entry) || Entry <- ets:tab2list(Tags) ] ),
    file:write_file(TagsFile, [Header, Entries]),
    ok.

tag_to_binary({{Tag, File, Scope, Kind}, TagAddress}) ->
    ScopeStr =
    case Scope of
        global -> "";
        local -> "\tfile:"
    end,
    iolist_to_binary([Tag, "\t",
                      File, "\t",
                      TagAddress, ";\"\t",
                      Kind,
                      ScopeStr, "\n"]).

%%%=============================================================================
%%% Utility functions
%%%=============================================================================

log(Format) ->
    log(Format, []).
log(Format, Data) ->
    case get(verbose) of
        true ->
            io:format(Format, Data);
        _ ->
            ok
    end.

log_error(Format, Data) ->
    io:format(standard_error, Format, Data).

print_help() ->
    Help =
"Usage: vim-erlang-tags.erl [-h|--help] [-v|--verbose] [-] [-o|--output FILE]
                            DIR_OR_FILE...

Description:
  vim-erlang-tags.erl creates a tags file that can be used by Vim. The
  directories given as arguments are searched (recursively) for *.erl and *.hrl
  files, which will be scanned. The files given as arguments are also scanned.
  The default is to search in the current directory.

Options:
  -h, --help    Print help and exit.
  -v, --verbose Verbose output.
  -             Read the list of files from the standard input.
  -o, --output FILE
                Write the output into the given file instead of ./tags.
  -i, --ignore FILE_WILDCARD
                Ignore the files/directories that match the given wildcard.
                Read http://www.erlang.org/doc/man/filelib.html#wildcard-1 for
                the wildcard patterns.
  \-p, --otp     Include the currently used OTP lib_dir

Example:
  $ vim-erlang-tags.erl
  $ vim-erlang-tags.erl .  # Same
  $ find . -name '*.[he]rl' | vim-erlang-tags.erl -  # Equivalent to the above
  $ vim-erlang-tags.erl /path/to/project1 /path/to/project2
",
    io:format("~s", [Help]).
