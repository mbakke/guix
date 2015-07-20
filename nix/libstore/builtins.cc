/* GNU Guix --- Functional package management for GNU
   Copyright (C) 2016 Ludovic Courtès <ludo@gnu.org>

   This file is part of GNU Guix.

   GNU Guix is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or (at
   your option) any later version.

   GNU Guix is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.  */

#include <builtins.hh>
#include <util.hh>

namespace nix {

static void builtinDownload(const Derivation & drv)
{
    // Make sure we get a fixed-output derivation.  If we did not check that,
    // then the result of our download would not be checked.
    if (!isFixedOutputDrv(drv)) {
	throw Error("'download' built-in function passed a derivation \
that is not fixed-output");
    }

    auto getAttr = [&](const string & name) {
        auto i = drv.env.find(name);
        if (i == drv.env.end()) throw Error(format("attribute '%s' missing") % name);
        return i->second;
    };


    // XXX: What if URL is "file:///etc/shadow"?  This since process is
    // running as root, users could tweak it into reading files they don't
    // have access to.  However, since this is a fixed-output derivation,
    // there's not much they could learn.
    auto url = getAttr("url");

    auto out = getAttr("out");

    // Invoke 'guix download'.
    Strings args;
    args.push_back("download");

    // Since DRV's output hash is known, X.509 certificate validation is
    // pointless.
    args.push_back("--no-check-certificate");

    args.push_back("-o");
    args.push_back(out);

    auto maybeMirrors = drv.env.find("mirrors");
    if (maybeMirrors != drv.env.end())
	args.push_back("--mirrors=" + maybeMirrors->second);

    args.push_back(url);
    runProgram("guix", true, args);

    auto executable = drv.env.find("executable");
    if (executable != drv.env.end() && executable->second == "1") {
        if (chmod(out.c_str(), 0755) == -1)
            throw SysError(format("making '%1%' executable") % out);
    }
}

static const std::map<std::string, derivationBuilder> builtins =
{
    { "download", builtinDownload }
};

derivationBuilder lookupBuiltinBuilder(const std::string & name)
{
    if (name.substr(0, 8) == "builtin:")
    {
	auto realName = name.substr(8);
	auto builder = builtins.find(realName);
	return builder == builtins.end() ? NULL : builder->second;
    }
    else
	return NULL;
}

}
