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

%%% The EtsTags ets table has the following scheme:
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
-define(RE_FUNCT_NEW,  ?COMPILE("^([a-z][a-zA-Z0-9_@]*)\\s*(\\((?>[^()]|(?R))*\\))")).
-define(RE_TYPESPECS1, ?COMPILE("^-\\s*(type|opaque)\\s*([a-zA-Z0-9_@]+)\\b")).
-define(RE_TYPESPECS2, ?COMPILE("^-\\s*(type|opaque)\\s*'([^ \\t']+)'")).
-define(RE_DEFINES1,   ?COMPILE("^-\\s*(record|define)\\s*\\(?\\s*([a-zA-Z0-9_@]+)\\b")).
-define(RE_DEFINES2,   ?COMPILE("^-\\s*(record|define)\\s*\\(?\\s*'([^ \\t']+)'")).

-define(DEFAULT_PATH, ".").

%%%=============================================================================
%%% Parameter types, maps, defaults
%%%============================================================================
-type command_type() :: stack | single_state | boolean.
-type command_type_stack() :: include | ignore | output.
-type command_type_single() :: match_mode | verbose.
-type command_type_boolean() :: otp | help.
-type cmd_param() :: command_type_stack() |
                     command_type_single() |
                     command_type_boolean().
-type cmd_line_arg() :: string().
-type cmd_line_arguments() :: [cmd_line_arg()].
-type match_mode() :: func_name_only | full_func_name_args.
-type parsed_params() ::
    #{include := list(string()),
      ignore := list(string()),
      output := list(string()),
      otp := boolean(),
      verbose := 0..2,
      help := boolean(),
      match_mode := match_mode()
     }.
-define(DEFAULT_PARSED_PARAMS,
        #{include => [],
          ignore => [],
          output => [],
          otp => false,
          verbose => 0,
          help => false,
          match_mode => func_name_only}).

-type config() ::
    #{explore := list(file:filename()),
      match_mode := match_mode(),
      output := file:filename()
     }.

-spec allowed_cmd_params() -> [{cmd_param(), cmd_line_arguments()}].
allowed_cmd_params() ->
    [
     {include, ["-i", "--include", "--"]},
     {ignore,  ["-g", "--ignore"]},
     {output,  ["-o", "--output"]},
     {otp,     ["-p", "--otp"]},
     {verbose, ["-v", "--verbose"]},
     {help,    ["-h", "--help"]},
     {match_mode,["-m","--match-mode"]}
    ].

-spec get_command_type(Cmd :: cmd_param()) -> command_type().
get_command_type(C) when C =:= include;
                         C =:= ignore;
                         C =:= output ->
    stack;
get_command_type(C) when C =:= otp;
                         C=:= help ->
    boolean;
get_command_type(C) when C =:= match_mode;
                         C =:= verbose ->
    single_state.

main(Args) ->
    log("Entering main. Args are ~p~n~n", [Args]),
    ParsedArgs = reparse_args(?DEFAULT_PARSED_PARAMS, Args),
    set_verbose_flag(maps:get(verbose, ParsedArgs, 0)),
    Opts = clean_opts(ParsedArgs),
    run(Opts).

run(#{help := true}) ->
    print_help();
run(#{explore := Explore, output := TagFile, match_mode := MM}) ->
    EtsTags = create_tags(Explore, MM),
    log("Tags created, time to save to file! :)"),
    ok = tags_to_file(EtsTags, TagFile),
    ets:delete(EtsTags).

set_verbose_flag(Verbose) when is_list(Verbose) ->
    put(verbose, list_to_integer(Verbose));
set_verbose_flag(Verbose) when is_integer(Verbose)->
    put(verbose, Verbose).

-spec reparse_args(parsed_params(), cmd_line_arguments()) -> parsed_params().
reparse_args(Opts, []) ->
    Opts;
reparse_args(Opts, AllArgs) ->
    {Param, ToContinueParsing} = parse_next_arg(AllArgs),
    {ParamState, NextArgs} =
        case get_command_type(Param) of
            boolean ->
                {true, ToContinueParsing};
            single_state ->
                {hd(ToContinueParsing), tl(ToContinueParsing)};
            stack ->
                get_all_args_for_param(
                  Param, maps:get(Param, Opts, []), ToContinueParsing)
    end,
    reparse_args(Opts#{Param := ParamState}, NextArgs).

-spec parse_next_arg(nonempty_list(cmd_line_arg())) ->
    {cmd_param(), cmd_line_arguments()}.
parse_next_arg([Arg | NextArgs] = AllArgs) ->
    lists:foldl(
      fun({Param, ParamList}, Acc) ->
              case lists:member(Arg, ParamList) of
                  true -> {Param, NextArgs};
                  _ -> Acc
              end
      end, %% If the parameter is not recognised, just throw it into include
      {include, AllArgs},
      allowed_cmd_params()).

%% Return args for the current parameter,
%% and the rest of the args to continue parsing
-spec get_all_args_for_param(Param, CurrentParamState, ToContinueParsing) -> Ret
    when Param :: command_type_stack(),
         CurrentParamState :: cmd_line_arguments(),
         ToContinueParsing :: cmd_line_arguments(),
         Ret :: {boolean(), cmd_line_arguments()}
         | {cmd_line_arguments(), cmd_line_arguments()}.
get_all_args_for_param(Param, CurrentParamState, ToContinueParsing) ->
    log("Parsing args for parameter ~p~n", [Param]),
    {StateArgs, Rest} = consume_until_new_command(ToContinueParsing),
    case StateArgs of
        [] -> log_error("Arguments needed for ~s.~n", [Param]);
        _ -> ok
    end,
    {StateArgs ++ CurrentParamState, Rest}.

-spec consume_until_new_command(Args) -> {ConsumedArgs, RestArgs} when
      Args :: cmd_line_arguments(),
      ConsumedArgs :: cmd_line_arguments(),
      RestArgs :: cmd_line_arguments().
consume_until_new_command(Args) ->
    log("    Consuming args ~p~n", [Args]),
    States = lists:foldl(
               fun({_,S}, Acc) -> S ++ Acc end, [], allowed_cmd_params()),
    lists:splitwith(
      fun("-" ++ _ = El) ->
              case lists:member(El, States) of
                  true -> false;
                  _ -> log_error("Unknown argument: ~s~n", [El]), halt(1)
              end;
         (_El) ->
              true
      end, Args).

-spec clean_opts(parsed_params()) -> config().
clean_opts(#{help := true}) ->
    #{help => true};
clean_opts(#{include := []} = Opts0) ->
    log("Set includes to default current dir.~n"),
    clean_opts(Opts0#{include := [?DEFAULT_PATH]});
clean_opts(#{otp := true, include := Inc} = Opts0) ->
    log("Including OTP in.~n"),
    AllIncludes = [code:lib_dir() | Inc],
    Opts1 = maps:update(include, AllIncludes, Opts0),
    Opts2 = maps:update(otp, false, Opts1),
    clean_opts(Opts2);
clean_opts(#{match_mode := GivenMode} = Opts0)
  when GivenMode =:= "full_name_only"; GivenMode =:= "full_func_name_args" ->
    Opts1 = maps:update(match_mode, list_to_existing_atom(GivenMode), Opts0),
    clean_opts(Opts1);
clean_opts(#{output := []} = Opts0) ->
    log("Set output to default 'tags'.~n"),
    clean_opts(Opts0#{output := ["tags"]});
clean_opts(#{include := Included, ignore := Ignored, output := [Output], match_mode := MM}) ->
    #{explore => to_explore_as_include_minus_ignored(Included, Ignored),
      output => Output,
      match_mode => MM
     }.

%% This function expands all the paths given in included and in ignored to
%% actual filenames, and then subtracts the excluded ones from the included
-spec to_explore_as_include_minus_ignored([string()], [string()]) ->
    [file:filename()].
to_explore_as_include_minus_ignored(Included, Ignored) ->
    AllIncluded = lists:append(expand_dirs(Included)),
    AllIgnored = lists:append(expand_dirs(Ignored)),
    lists:subtract(AllIncluded, AllIgnored).

-spec expand_dirs([string()]) -> [file:filename()].
expand_dirs(Included) ->
    lists:map(fun expand_dirs_or_filenames/1, Included).

-spec expand_dirs_or_filenames(string()) -> [file:filename()].
expand_dirs_or_filenames(FileName) ->
    case {filelib:is_file(FileName), filelib:is_dir(FileName)} of
        {false, _} ->
            log_error("File \"~p\" is not a proper file.~n", [FileName]),
            [];
        {true, true} ->
                    filelib:wildcard(FileName ++ "/**/*.{erl,hrl}");
        _ -> [FileName]
    end.

%%%=============================================================================
%%% Create tags from directory trees and file lists
%%%================================================================================================

% Read the given Erlang source files and return an ets table that contains the appropriate tags.
-spec create_tags([file:filename()], match_mode()) -> ets:tid().
create_tags(Explore, MM) ->
    log("In create_tags, To explore: ~p~n", [Explore]),
    EtsTags = case MM of
                  func_name_only ->
                      ets:new(tags,
                              [set, public,
                               {write_concurrency,true},
                               {read_concurrency,false}
                              ]);
                  full_func_name_args ->
                      ets:new(tags,
                              [bag, public,
                               {write_concurrency,true},
                               {read_concurrency,false}
                              ])
              end,
    log("EtsTags table created.~nStart Processing of files~n"),
    explore_files(Explore, MM, EtsTags),
    log("All files processed~n", []),
    EtsTags.

explore_files(Explore, MM, EtsTags) ->
    Processes = process_filenames(Explore, MM, EtsTags, []),
    HowMany = length(Processes),
    log("Waiting for ~p files to be processed ~n", [HowMany]),
    timer:sleep(HowMany div 2),
    log("Main process info: ~p~n", [erlang:process_info(self(), message_queue_len)]),
    lists:foreach(
      fun({Pid, Ref}) ->
              receive
                  {'DOWN', Ref, process, Pid, normal} -> ok
              after 5000 ->
                        log_error("Late Pid ~p~n", [erlang:process_info(Pid)]),
                        error("Some process takes too long")
              end
      end,
      Processes).

% Go through the given files: scan the Erlang files for tags
% Here we now for sure that `Files` are indeed files with extensions *.erl or *.hrl.
-spec process_filenames(Files, MM, EtsTags, Processes) -> RetProcesses when
      Files :: [file:filename()],
      MM :: match_mode(),
      EtsTags :: ets:tid(),
      Processes :: [{pid(), reference()}],
      RetProcesses :: [{pid(), reference()}].
process_filenames([], _MM, _Tags, Processes) ->
    Processes;
process_filenames([File|OtherFiles], MM, EtsTags, Processes) ->
    Verbose = case get(verbose) of X when X =:=0 -> 0; Y -> Y end,
    P = spawn_monitor(fun() -> add_tags_from_file(File, EtsTags, MM, Verbose) end),
    process_filenames(OtherFiles, MM, EtsTags, [P | Processes]).

%%%=============================================================================
%%% Scan a file or line for tags
%%%=============================================================================

% Read the given Erlang source file and add the appropriate tags to the EtsTags ets table.
add_tags_from_file(File, EtsTags, MM, Verbose) ->
    set_verbose_flag(Verbose),
    log("~nProcessing file: ~s~n", [File]),

    BaseName = filename:basename(File), % e.g. "mymod.erl"
    ModName = filename:rootname(BaseName), % e.g. "mymod"
    add_file_tag(EtsTags, File, BaseName, ModName),

    case file:read_file(File) of
        {ok, Contents} -> ok = scan_tags(Contents, MM, {EtsTags, File, ModName});
        Err -> log_error("File ~s not readable: ~p~n", [File, Err])
    end.

scan_tags(Contents, MM, {EtsTags, File, ModName}) ->
    FuncRegex = case MM of
                    func_name_only -> ?RE_FUNCTIONS;
                    full_func_name_args -> ?RE_FUNCT_NEW
                end,
    scan_tags_core(
      Contents, FuncRegex,
      fun(Match) ->
              add_func_tags(EtsTags, File, ModName, Match, MM)
      end),
    scan_tags_core(
      Contents, ?RE_TYPESPECS1,
      fun([_, Attr, TypeName]) ->
              InnerPattern = [TypeName, "\\>"],
              add_type_tags(EtsTags, File, ModName, Attr, TypeName, InnerPattern)
      end),
    scan_tags_core(
      Contents, ?RE_TYPESPECS2,
      fun([_, Attr, TypeName]) ->
              InnerPattern = [$', TypeName, $'],
              add_type_tags(EtsTags, File, ModName, Attr, TypeName, InnerPattern)
      end),
    scan_tags_core(
      Contents, ?RE_DEFINES1,
      fun([_, Attr, Name]) ->
              InnerPattern = [Name, "\\>"],
              add_record_or_macro_tag(EtsTags, File, Attr, Name, InnerPattern)
      end),
    scan_tags_core(
      Contents, ?RE_DEFINES2,
      fun([_, Attr, Name]) ->
              InnerPattern = [$', Name, $'],
              add_record_or_macro_tag(EtsTags, File, Attr, Name, InnerPattern)
      end),
    ok.

scan_tags_core(Contents, Pattern, Fun) ->
    case re:run(Contents, Pattern, [{capture, all, binary}, global]) of
        nomatch ->
            ok;
        {match, Matches} ->
            case length(Matches) >= 1000 of
                true ->
                    {ToMatch, _} = lists:foldl(
                                fun([_,NewFunc|_] = El, {[[_,FuncName|_]|_]=L,N}) ->
                                        case {NewFunc =:= FuncName, N < 20} of
                                            {false, _} -> {[El | L], 0};
                                            {true, true} -> {[El | L], N+1};
                                            {true, false} -> {L, N}
                                        end;
                                   (El, {[], N}) -> {[El], N}
                                end,
                                {[], 0},
                               Matches),
                    lists:foreach(Fun, ToMatch);
                _ -> lists:foreach(Fun, Matches)
            end
    end.

%%%=============================================================================
%%% Add specific tags
%%%=============================================================================

% Add this information to EtsTags.
add_file_tag(EtsTags, File, BaseName, ModName) ->

    % myfile.hrl <tab> ./myfile.hrl <tab> 1;"  F
    % myfile.erl <tab> ./myfile.erl <tab> 1;"  F
    % myfile <tab> ./myfile.erl <tab> 1;"  M
    add_tag(EtsTags, BaseName, File, "1", global, $F),

    case filename:extension(File) of
        ".erl" ->
            add_tag(EtsTags, ModName, File, "1", global, $M);
        _ ->
            ok
    end.

% File contains the function ModName:FuncName; add this information to EtsTags.
add_func_tags(EtsTags, File, ModName, [_, FuncName, UnsafeArgs], full_func_name_args) ->
    Args = binary:replace(UnsafeArgs, <<"\n">>, <<"\\n">>, [global]),
    log("Function definition found: ~s~n      ~s~n", [FuncName, Args]),
    TagVal = ["/^", FuncName, Args, "/"],
    add_tag(EtsTags, [ModName, ":", FuncName], File, TagVal, global, $f),
    add_tag(EtsTags, FuncName, File, TagVal, local, $f);
add_func_tags(EtsTags, File, ModName, [_,FuncName], func_name_only) ->

    log("Function definition found: ~s~n", [FuncName]),

    % Global entry:
    % mymod:f <tab> ./mymod.erl <tab> /^f\>/
    add_tag(EtsTags, [ModName, ":", FuncName], File, ["/^", FuncName, "\\>/"],
            global, $f),

    % Static (or local) entry:
    % f <tab> ./mymod.erl <tab> /^f\>/ <space><space> ;" <tab> file:
    add_tag(EtsTags, FuncName, File, ["/^", FuncName, "\\>/"], local, $f).

% File contains the type ModName:Type; add this information to EtsTags.
add_type_tags(EtsTags, File, ModName, Attribute, TypeName, InnerPattern) ->

    log("Type definition found: ~s~n", [TypeName]),

    Pattern = ["/^-\\s\\*", Attribute, "\\s\\*", InnerPattern, $/],

    % Global entry:
    % mymod:mytype <tab> ./mymod.erl <tab> /^-type\s\*mytype\>/
    % mymod:mytype <tab> ./mymod.erl <tab> /^-opaque\s\*mytype\>/
    add_tag(EtsTags, [ModName, ":", TypeName], File, Pattern, global, $t),

    % Static (or local) entry:
    % mytype <tab> ./mymod.erl <tab> /^-type\s\*mytype\>/
    %     <space><space> ;" <tab> file:
    % mytype <tab> ./mymod.erl <tab> /^-opaque\s\*mytype\>/
    %     <space><space> ;" <tab> file:
    add_tag(EtsTags, TypeName, File, Pattern, local, $t).

% File contains a macro or record called Name; add this information to EtsTags.
add_record_or_macro_tag(EtsTags, File, Attribute, Name, InnerPattern) ->

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
    add_tag(EtsTags, Name, File,
            ["/^-\\s\\*", Attribute, "\\s\\*(\\?\\s\\*", InnerPattern, "/"],
            Scope, Kind),

    % #myrec  ./mymod.erl  /^-record\s\*\<myrec\>/;"  r  file:
    % #myrec  ./myhrl.hrl  /^-record\s\*\<myrec\>/;"  r
    % ?mymac  ./mymod.erl  /^-define\s\*\<mymac\>/;"  m  file:
    % ?mymac  ./myhrl.hrl  /^-define\s\*\<mymac\>/;"  m
    add_tag(EtsTags, [Prefix|Name], File,
            ["/^-\\s\\*", Attribute, "\\s\\*(\\?\\s\\*", InnerPattern, "/"],
            Scope, Kind).

add_tag(EtsTags, Tag, File, TagAddress, Scope, Kind) ->
    ets:insert(EtsTags, {{Tag, File, Scope, Kind}, TagAddress}).

%%%=============================================================================
%%% Writing tags into a file
%%%=============================================================================

tags_to_file(EtsTags, TagsFile) ->
    Header = "!_TAG_FILE_SORTED\t1\t/0=unsorted, 1=sorted/\n",
    Entries = lists:sort(
                [tag_to_binary(Entry) || Entry <- ets:tab2list(EtsTags)]),
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
        N when N >= 1 ->
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
  -p, --otp     Include the currently used OTP lib_dir

Example:
  $ vim-erlang-tags.erl
  $ vim-erlang-tags.erl .  # Same
  $ find . -name '*.[he]rl' | vim-erlang-tags.erl -  # Equivalent to the above
  $ vim-erlang-tags.erl /path/to/project1 /path/to/project2
",
    io:format("~s", [Help]).
