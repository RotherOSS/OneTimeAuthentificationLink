# --
# OTOBO is a web-based ticketing system for service organisations.
# --
# Copyright (C) 2001-2020 OTRS AG, https://otrs.com/
# Copyright (C) 2019-2021 Rother OSS GmbH, https://otobo.de/
# --
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# --

package Kernel::System::PostMaster::Filter::CreateNewCustomerUser;

use strict;
use warnings;

use Kernel::System::VariableCheck qw(:all);

our @ObjectDependencies = (
    'Kernel::System::CustomerUser',
    'Kernel::System::Log',
);

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    # get parser object
    $Self->{ParserObject} = $Param{ParserObject} || die "Got no ParserObject!";

    # Get communication log object.
    $Self->{CommunicationLogObject} = $Param{CommunicationLogObject} || die "Got no CommunicationLogObject!";

    return $Self;
}

sub Run {
    my ( $Self, %Param ) = @_;

    # only needed for new tickets
    return 1 if $Param{TicketID};

    # check needed stuff
    for (qw(GetParam JobConfig)) {
        if ( !$Param{$_} ) {
            $Self->{CommunicationLogObject}->ObjectLog(
                ObjectLogType => 'Message',
                Priority      => 'Error',
                Key           => 'Kernel::System::PostMaster::Filter::CreateNewCustomerUser',
                Value         => "Need $_!",
            );
            return;
        }
    }

    my @EmailAddressOnField = $Self->{ParserObject}->SplitAddressLine(
        Line => $Self->{ParserObject}->GetParam( WHAT => 'From' ),
    );

    my $IncomingMailAddress;

    for my $EmailAddress (@EmailAddressOnField) {
        $IncomingMailAddress = $Self->{ParserObject}->GetEmailAddress(
            Email => $EmailAddress,
        );
    }

    return 1 if !$IncomingMailAddress;

    my $CustomerUserObject = $Kernel::OM->Get('Kernel::System::CustomerUser');

    my %List = $CustomerUserObject->CustomerSearch(
        PostMasterSearch => lc( $IncomingMailAddress ),
        Valid            => 0,
    );

    # user already exists
    if ( %List ) {

        # return if no X-OTOBO-CustomerUser spoofing is possible/dangerous
        return 1 if !$Param{JobConfig}{CustomerHeaderSpoofProtection};

        my %CustomerData;
        LOGIN:
        for my $UserLogin ( sort keys %List ) {
            my %CustomerUser = $CustomerUserObject->CustomerUserDataGet(
                User => $UserLogin,
            );
            
            if ( $CustomerUser{ValidID} == 1 ) {
                %CustomerData = %CustomerUser;
                last LOGIN;
            }
        }

        # if user exists but is not valid, do nothing
        return 1 if !%CustomerData;

        # take CustomerID from customer backend lookup or from from field
        if ( $CustomerData{UserLogin} ) {
            $GetParam{'X-OTOBO-CustomerUser'} = $CustomerData{UserLogin};

            # notice that UserLogin is from customer source backend
            $Self->{CommunicationLogObject}->ObjectLog(
                ObjectLogType => 'Message',
                Priority      => 'Notice',
                Key           => 'Kernel::System::PostMaster::Filter::CreateNewCustomerUser',
                Value         => "Take UserLogin ($CustomerData{UserLogin}) from "
                    . "customer source backend based on ($IncomingMailAddress).",
            );
        }
        if ( $CustomerData{UserCustomerID} ) {
            $GetParam{'X-OTOBO-CustomerNo'} = $CustomerData{UserCustomerID};

            # notice that UserCustomerID is from customer source backend
            $Self->{CommunicationLogObject}->ObjectLog(
                ObjectLogType => 'Message',
                Priority      => 'Notice',
                Key           => 'Kernel::System::PostMaster::Filter::CreateNewCustomerUser',
                Value         => "Take UserCustomerID ($CustomerData{UserCustomerID})"
                    . " from customer source backend based on ($IncomingMailAddress).",
            );
        }
    }

    # user does not yet exist - create it!
    else {
        my $UserLogin = lc( $IncomingMailAddress );
        
        my $Success = $CustomerUserObject->CustomerUserAdd(
            Source         => $Param{JobConfig}{CustomerUserBackend} || 'CustomerUser',
#            UserFirstname  => '',
#            UserLastname   => '',
            UserCustomerID => $UserLogin,
            UserLogin      => $UserLogin,
            UserEmail      => $UserLogin,
            ValidID        => 1,
            UserID         => 1,
        );

        if ( $Success ) {
            # notice that UserLogin is from customer source backend
            $Self->{CommunicationLogObject}->ObjectLog(
                ObjectLogType => 'Message',
                Priority      => 'Notice',
                Key           => 'Kernel::System::PostMaster::Filter::CreateNewCustomerUser',
                Value         => "Create and set new UserLogin ($CustomerData{UserLogin}).",
            );

            $GetParam{'X-OTOBO-CustomerUser'} = $UserLogin;
            $GetParam{'X-OTOBO-CustomerNo'}   = $UserLogin;
        }
    }

    return 1;
}

1;
