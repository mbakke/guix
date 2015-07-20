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

/* Interface to built-in derivation builders.  */

#pragma once

#include <derivations.hh>
#include <map>
#include <string>

namespace nix {

    inline bool isBuiltin(const Derivation & drv)
    {
	return string(drv.builder, 0, 8) == "builtin:";
    }

    typedef void (*derivationBuilder) (const Derivation &);

    /* Return the built-in builder called BUILDER, or NULL if none was
       found.  */
    derivationBuilder lookupBuiltinBuilder(const std::string &builder);
}
