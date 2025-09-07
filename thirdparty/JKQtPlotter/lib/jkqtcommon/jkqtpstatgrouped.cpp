/*
    Copyright (c) 2008-2020 Jan W. Krieger (<jan@jkrieger.de>)

    last modification: $LastChangedDate$  (revision $Rev$)

    This software is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License (LGPL) as published by
    the Free Software Foundation, either version 2.1 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License (LGPL) for more details.

    You should have received a copy of the GNU Lesser General Public License (LGPL)
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/



#include "jkqtpstatgrouped.h"

double jkqtpstatGroupingIdentity1D(double v) {
    return v;
}

double jkqtpstatGroupingRound1D(double v) {
    return round(v);
}

double jkqtpstatGroupingCustomRound1D(double v, double firstGroupCenter, double groupWidth) {
    return round((v-firstGroupCenter)/(2.0*groupWidth));
}


JKQTPStatGroupDefinitionFunctor1D jkqtpstatMakeGroupingCustomRound1D(double firstGroupCenter, double groupWidth)
{
    return std::bind(&jkqtpstatGroupingCustomRound1D, std::placeholders::_1, firstGroupCenter, groupWidth);
}
