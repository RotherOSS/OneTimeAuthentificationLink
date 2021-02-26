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
        SQL => "SELECT Used,User,TicketNumber FROM $Self->{Table} WHERE Token = ?",
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

            $Self->SendNewToken(
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
        if ( !$Param{$Needed} ) {
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
        if ( !$Param{$Needed} ) {
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
        if ( !$Param{$Needed} ) {
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

sub TicketLink {
    my ( $Self, %Param ) = @_;

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');

    # check needed stuff
    for my $Needed ( qw/TicketNumber User/ ) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!"
            );

            return $ConfigObject->Get('OneTimeAuth::CustomerErrorMessage') // 'Link could not be generated, please contact us directly!';
        }
    }

    my $TicketLink = $ConfigObject->Get('HttpType') . '://' . $ConfigObject->Get('FQDN') . '/otobo/customer.pl';
    $TicketLink .= "?Action=CustomerTicketZoom;TicketNumber=$Param{TicketNumber}";

    # check if the user already has a passsword - then no direct link is needed
    my %User = $Kernel::OM->Get('Kernel::System::CustomerUser')->CustomerUserDataGet(
        User => $Param{User},
    );

    unless ( $User{UserPassword} ) {
        # generate token
        my $Token = $Self->GenerateToken(
            %Param,
        );

        if ( !$Token ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Error in token generation!"
            );

            return $ConfigObject->Get('OneTimeAuth::CustomerErrorMessage') // 'Link could not be generated, please contact us directly!';
        }

        $TicketLink .= ";OTAToken=$Token";
    }

    return $TicketLink;
}

sub DeactivateClosedTickets {
    my ( $Self, %Param ) = @_;

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');
    my $TicketObject = $Kernel::OM->Get('Kernel::System::Ticket');

    $Self->{DBObject}->Prepare(
        SQL => "SELECT DISTINCT(ticket_number) FROM $Self->{Table}",
    );

    # get the compare time if a delay is given
    my $Delay       = $Kernel::OM->Get('Kernel::Config')->Get('OneTimeAuth::AccessDaysAfterClose') || 0;
    my $StillOKTime = $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch() - 24*60*60*$Delay;

    TICKET:
    while ( my @Row = $DBObject->FetchrowArray() ) {
        my $TicketID = $TicketObject->TicketIDLookup(
            TicketNumber => $Row[0],
        );

        my %Ticket = $TicketObject->TicketGet(
            TicketID => $TicketID,
        );

        # remove old tokens
        if ( $Ticket{StateType} eq 'closed' || $Ticket{StateType} eq 'removed' || $Ticket{StateType} eq 'merged' ) {
            if ( $Delay ) {
                my $LastChangedTime = $Kernel::OM->Create(
                    'Kernel::System::DateTime',
                    ObjectParams => {
                        String   => $Ticket{Changed},
                    }
                )->ToEpoch();

                next TICKET if $LastChangedTime > $StillOKTime;
            }

            $Self->DeleteTicketTokens(
                TicketNumber => $Ticket{TicketNumber},
            );
        }
    }

    return 1;
}

sub SendNewToken {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    for my $Needed ( qw/TicketNumber User/ ) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!"
            );

            return $ConfigObject->Get('OneTimeAuth::CustomerErrorMessage') // 'Link could not be generated, please contact us directly!';
        }
    }

    my $ConfigObject       = $Kernel::OM->Get('Kernel::Config');
    my $CustomerUserObject = $Kernel::OM->Get('Kernel::System::CustomerUser');
    my $TicketObject       = $Kernel::OM->Get('Kernel::System::Ticket');

    my $TicketID = $TicketObject->TicketIDLookup(
        TicketNumber => $Param{TicketNumber},
    );
    my %Ticket = $TicketObject->TicketGet(
        TicketID => $TicketID,
    );
    my %User = $Kernel::OM->Get('Kernel::System::CustomerUser')->CustomerUserDataGet(
        User => $Param{User},
    );

    my $TemplateGenerator = $Kernel::OM->Get('Kernel::System::TemplateGenerator');
    my $Sender            = $TemplateGenerator->Sender(
        QueueID => $Ticket{QueueID},
        UserID  => 1,
    );

    my $TicketLink = $Self->TicketLink( %Param );

    my $EmailObject = $Kernel::OM->Get('Kernel::System::Email');
    my $Sent = $SendObject->Send(
        From     => $Sender,
        To       => $User{UserEmail},
        Subject  => 'New TicketLink',
        Charset  => 'iso-8859-15',
        MimeType => 'text/html',
        Body     => "Hello hello,<br/>please click sis link: $TicketLink",
#        InReplyTo     => '<somemessageid-2@example.com>',
#        References    => '<somemessageid-1@example.com> <somemessageid-2@example.com>',
#        Loop          => 1, # not required, removes smtp from
#        CustomHeaders => {
#            X-OTOBO-MyHeader => 'Some Value',
#        },
    );

    return 1;
}

1;
