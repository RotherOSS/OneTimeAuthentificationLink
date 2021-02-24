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

package Kernel::System::CustomerAuth::OneTimeAuthLink;

use strict;
use warnings;

use Crypt::PasswdMD5 qw(unix_md5_crypt apache_md5_crypt);
use Digest::SHA;

our @ObjectDependencies = (
    'Kernel::Config',
    'Kernel::System::CustomerUser',
    'Kernel::System::DB',
    'Kernel::System::Log',
);

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    # get database object
    $Self->{DBObject} = $Kernel::OM->Get('Kernel::System::DB');
    
    $Self->{Table} = 'OTATokens';

    return $Self;
}

sub GetOption {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    if ( !$Param{What} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Need What!"
        );
        return;
    }

    # module options
    my %Option = (
        PreAuth => 0,
    );

    # return option
    return $Option{ $Param{What} };
}

sub ExtendedParamNames {
    my ( $Self, %Param ) = @_;
    
    return qw/OTAToken/;
}

sub Auth {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    if ( !$Param{OTAToken} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'debug',
            Message  => "No Token provided!"
        );
        return;
    }

    $Self->{DBObject}->Prepare(
        SQL => "
            SELECT Used,User,TicketNumber FROM $Self->{Table} WHERE
            Token = ?
            ",
        Bind => [ \$Param{OTAToken} ],
    );

    my ( $Used, $User, $TicketNumber ) = $Self->{DBObject}->FetchrowArray() || ( 0 );

    return if ( !$Used || !$User );

    my $CustomerUserObject = $Kernel::OM->Get('Kernel::System::CustomerUser');

    # send out new email if the ticket is still considered active but no current link exists
    if ( $Used == 1 ) {
        # store failed login count
        my %CustomerData = $CustomerUserObject->CustomerUserDataGet( User => $Param{User} );
        if (%CustomerData) {
            my $Count = $CustomerData{UserLoginFailed} || 0;
            $Count++;
            $CustomerUserObject->SetPreferences(
                Key    => 'UserLoginFailed',
                Value  => $Count,
                UserID => $CustomerData{UserLogin},
            );
        }

        # check whether active login link still exists
        $Self->{DBObject}->Prepare(
            SQL => "
                SELECT User FROM $Self->{Table} WHERE
                TicketNumber = ? AND Used = ?
                ",
            Bind => [ \$Param{OTAToken}, \2 ],
        );

        if ( $Self->{DBObject}->FetchrowArray() ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'debug',
                Message  => "CustomerUser '$User' tried to log in with an old token. New token exists - nothing to do."
            );
        }
        else {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'debug',
                Message  => "CustomerUser '$User' tried to log in with an old token. No active token left - sending a new one via mail."
            );

            $Self->GenerateToken(
                User         => $User,
                TicketNumber => $TicketNumber,
            );
        }

        return;
    }
    elsif ( $Used == 2 ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'debug',
            Message  => "CustomerUser '$User' logged in via token."
        );

        $Self->DeactivateTicketTokens(
            TicketNumber => $TicketNumber,
        );

        return $User;
    }

    return;

}

sub GenerateToken {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    for my $Needed ( qw/User TicketNumber/ ) {
        if ( !$Needed ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!"
            );
            return;
        }
    }

    # deactivate all other tokens for this ticket
    $Self->DeactivateTicketTokens(
        TicketNumber => $TicketNumber,
    );

    my $OTATokenLength = 24;
    my $RandomString;

    my $Try = 1;
    while ( $Try ) {
        $RandomString = $Kernel::OM->Get('Kernel::System::Main')->GenerateRandomString(
            Length => $OTATokenLength,
        );

        # check whether the string already exists
        $Self->{DBObject}->Prepare(
            SQL => "SELECT user FROM $Self->{Table} WHERE token = ?",
            Bind => [ \$Param{OTAToken} ],
        );

        if ( $Self->{DBObject}->FetchrowArray() ) {
            $Try++;
        }
        else {
            $Try = 0;
        }

        if ( $Try > 5 ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Could not generate a unique random string after five retries - something is not right!"
            );
            return;
        }
    }

    return if !$Self->{DBObject}->Do(
        SQL => "INSERT INTO $Self->{Table} ( token, ticket_number, used, user, create_time, change_time )
            VALUES ( ?, ?, ?, ?, current_timestamp, current_timestamp )",
        Bind => [ \$RandomString, \$TicketNumber, \2, \$User ],
    );
    
    return $RandomString;

}

sub DeactivateTicketTokens {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    for my $Needed ( qw/TicketNumber/ ) {
        if ( !$Needed ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!"
            );
            return;
        }
    }

    return if !$Self->{DBObject}->Do(
        SQL => "UPDATE $Self->{Table} SET used = 1, change_time = current_timestamp WHERE ticket_number = ? AND used = 2",
        Bind => [ \$TicketNumber ],
    );

    return 1;

}

sub DeleteTicketTokens {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    for my $Needed ( qw/TicketNumber/ ) {
        if ( !$Needed ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!"
            );
            return;
        }
    }

    return if !$Self->{DBObject}->Do(
        SQL => "DELETE FROM $Self->{Table} WHERE ticket_number = ?",
        Bind => [ \$TicketNumber ],
    );

    return 1;

}

1;
